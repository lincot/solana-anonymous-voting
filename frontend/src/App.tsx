import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  BrowserRouter,
  Link,
  Navigate,
  NavLink,
  Outlet,
  Route,
  Routes,
  useParams,
} from "react-router";
import { useFieldArray, useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { Connection, PublicKey, Transaction } from "@solana/web3.js";
import {
  ConnectionProvider,
  useWallet,
  WalletProvider,
} from "@solana/wallet-adapter-react";
import {
  WalletModalProvider,
  WalletMultiButton,
} from "@solana/wallet-adapter-react-ui";
import {
  LedgerWalletAdapter,
  SolflareWalletAdapter,
} from "@solana/wallet-adapter-wallets";
import * as anchor from "@coral-xyz/anchor";
import { WebUploader } from "@irys/web-upload";
import { WebSolana } from "@irys/web-upload-solana";
import { del as idbDel, get as idbGet, set as idbSet } from "idb-keyval";
import {
  type BabyJub,
  buildBabyjub,
  buildEddsa,
  buildPoseidon,
  type Eddsa,
  type Poseidon,
} from "circomlibjs";
import { groth16 } from "snarkjs";
import { poseidonDecrypt, poseidonEncrypt } from "@zk-kit/poseidon-cipher";
import { compressProof } from "../../helpers/compressSolana.ts";
import { genBabyJubKeypair, prv2sk } from "../../helpers/key.ts";
import {
  createPoll,
  createTally,
  cuLimitInstruction,
  fetchPlatformConfig,
  finishTally,
  type InstructionWithCu,
  PLATFORM_NAME,
  setProvider as setAnonProvider,
  tallyBatch,
  vote,
} from "@lincot/anon-vote-sdk";
import "@solana/wallet-adapter-react-ui/styles.css";
import type BaseWebIrys from "@irys/web-upload/esm/base";
import { getMerkleProof, getMerkleRoot } from "../../helpers/merkletree.ts";
import { hexToBytes32, replacer, reviver } from "../../helpers/utils.ts";
import { mulPointEscalar } from "@zk-kit/baby-jubjub";
import {
  ErrEntryIndexAlreadyExists,
  InMemoryDB,
  Merkletree,
  ZERO_HASH,
} from "@iden3/js-merkletree";
import "./index.css";
import { bytesToHex } from "@noble/hashes/utils";

const MAX_CHOICES = 8;
const CENSUS_DEPTH = 40;
const STATE_DEPTH = 64;
const MAX_BATCH = 6;

export const CLUSTER = (import.meta.env.VITE_CLUSTER) as
  | "devnet"
  | "mainnet";
export const RPC_URL = import.meta.env.VITE_RPC_URL as string;
export const INDEXER_URL = import.meta.env.VITE_INDEXER_URL as string;
export const OTHER_ENV_URL = import.meta.env.VITE_OTHER_ENV_URL as
  | string
  | undefined;
const GITHUB_URL = import.meta.env.VITE_GITHUB_URL;

const VOTE_WASM_URL = "/zk/Vote/Vote.wasm";
const VOTE_ZKEY_URL = "/zk/Vote/groth16_pkey.zkey";
const TALLY_WASM_URL = "/zk/Tally/Tally.wasm";
const TALLY_ZKEY_URL = "/zk/Tally/groth16_pkey.zkey";

const MAX_POLL_DURATION = 365 * 24 * 60 * 60;
const ONE_DAY_MS = 24 * 60 * 60 * 1000;

function useTheme() {
  const getInitial = () => {
    const saved = localStorage.getItem("theme");
    if (saved === "dark" || saved === "light") return saved as "dark" | "light";
    return window.matchMedia?.("(prefers-color-scheme: dark)")?.matches
      ? "dark"
      : "light";
  };
  const [theme, setTheme] = useState<"dark" | "light">(getInitial);
  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    localStorage.setItem("theme", theme);
  }, [theme]);
  return { theme, setTheme };
}

const ThemeToggle: React.FC = () => {
  const { theme, setTheme } = useTheme();
  return (
    <button
      type="button"
      className="rounded-lg border px-3 py-2 text-sm dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800"
      onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
      title="Toggle theme"
    >
      {theme === "dark" ? "☀️" : "🌙"}
    </button>
  );
};

const cn = (...x: Array<string | false | null | undefined>) =>
  x.filter(Boolean).join(" ");

const Card: React.FC<
  React.PropsWithChildren<{ title?: string; className?: string }>
> = ({ title, className, children }) => (
  <div
    className={cn(
      "max-w-3xl mx-auto rounded-2xl shadow p-4 border bg-white/80 border-gray-200",
      "dark:bg-neutral-900/80 dark:border-neutral-800",
      className,
    )}
  >
    {title && <h2 className="text-lg font-semibold mb-3">{title}</h2>}
    {children}
  </div>
);

type BabyJubKeypair = {
  name: string;
  prv: Uint8Array;
  sk: bigint;
  pub: [bigint, bigint];
  createdAt: number;
};

type EncryptedKeyringBlob = {
  v: 1;
  saltB64: string;
  ivB64: string;
  ctB64: string;
};

type RevoKey = {
  prv: Uint8Array;
  sk: bigint;
  pub: [bigint, bigint];
  updatedAt: number;
  title: string;
};

async function pbkdf2(pass: string, salt: Uint8Array) {
  const te = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    te.encode(pass),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: Buffer.from(salt),
      iterations: 250_000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  return key;
}

async function encryptToBlob<T>(
  pass: string,
  obj: T,
): Promise<EncryptedKeyringBlob> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await pbkdf2(pass, salt);
  const pt = new TextEncoder().encode(JSON.stringify(obj, replacer));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt),
  );
  return {
    v: 1,
    saltB64: btoa(String.fromCharCode(...salt)),
    ivB64: btoa(String.fromCharCode(...iv)),
    ctB64: btoa(String.fromCharCode(...ct)),
  };
}

async function decryptFromBlob<T>(
  pass: string,
  blob: EncryptedKeyringBlob,
): Promise<T> {
  const salt = Uint8Array.from(atob(blob.saltB64), (c) => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(blob.ivB64), (c) => c.charCodeAt(0));
  const ct = Uint8Array.from(atob(blob.ctB64), (c) => c.charCodeAt(0));
  const key = await pbkdf2(pass, salt);
  const pt = new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct),
  );
  return JSON.parse(new TextDecoder().decode(pt), reviver);
}

const toBytes32 = (n: bigint) => {
  const out = new Uint8Array(32);
  let x = n;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
};

function toHex32(n: bigint) {
  const out = new Uint8Array(32);
  let x = n;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return "0x" +
    Array.from(out).map((b) => b.toString(16).padStart(2, "0")).join("");
}

const bytes32ToBig = (u8: Uint8Array, off: number) => {
  let x = 0n;
  for (let i = 0; i < 32; i++) x = (x << 8n) | BigInt(u8[off + i]);
  return x;
};

const idForAccount = (a: BabyJubKeypair) => `${a.pub[0]}:${a.pub[1]}`;

async function genBabyJubKeypair_(name: string): Promise<BabyJubKeypair> {
  const eddsa = await getEddsa();
  const babyjub = await getBabyjub();
  const F = babyjub.F;
  const { prv, sk, pub } = genBabyJubKeypair(babyjub, eddsa);
  return {
    name,
    prv,
    sk,
    pub: [F.toObject(pub[0]), F.toObject(pub[1])],
    createdAt: Date.now(),
  };
}

type RevoKeysMapType = Record<
  string, /*accountId*/
  Record<string, /*pollId*/ RevoKey>
>;

type RevoKeysCtx = {
  loaded: boolean;
  map: RevoKeysMapType;
  reload: () => Promise<void>;
  getForPoll: (accountId: string, pollId: bigint) => RevoKey | null;
  generateForPoll: () => Promise<RevoKey>;
  setForPoll: (accountId: string, pollId: bigint, rk: RevoKey) => Promise<void>;
  removeForPoll: (accountId: string, pollId: bigint) => Promise<void>;
  exportJson: () => void;
  exportRevo: (accountId: string, filename?: string) => void;
};

const RevoKeysContext = createContext<RevoKeysCtx | null>(null);

export const RevoKeysProvider: React.FC<React.PropsWithChildren> = (
  { children },
) => {
  const KR = useKeyringCtx();
  const [map, setMap] = useState<RevoKeysMapType>({});
  const [loaded, setLoaded] = useState(false);

  const reload = useCallback(async () => {
    if (KR.locked) return;
    const blob = (await idbGet(REVO_DB_KEY)) as
      | EncryptedKeyringBlob
      | undefined;
    if (!blob) {
      setMap({});
      setLoaded(true);
      return;
    }
    try {
      const obj = await decryptFromBlob<RevoKeysMapType>(KR.pass, blob);
      setMap(obj || {});
    } catch {
      setMap({});
    } finally {
      setLoaded(true);
    }
  }, [KR.locked, KR.pass]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const persist = useCallback(async (next: RevoKeysMapType) => {
    if (KR.locked) return;
    const blob = await encryptToBlob(KR.pass, next);
    await idbSet(REVO_DB_KEY, blob);
    setMap(next); // notify all consumers immediately
  }, [KR.locked, KR.pass]);

  const getForPoll = useCallback((accountId: string, pollId: bigint) => {
    const m = map[accountId] || {};
    return m[String(pollId)] ?? null;
  }, [map]);

  const generateForPoll = useCallback(async () => {
    const { prv, sk, pub } = await genBabyJubKeypair_("");
    return { prv, sk, pub, updatedAt: Date.now() } as RevoKey;
  }, []);

  const setForPoll = useCallback(
    async (accountId: string, pollId: bigint, rk: RevoKey) => {
      const m = { ...(map[accountId] || {}) };
      m[String(pollId)] = rk;
      const next = { ...map, [accountId]: m };
      await persist(next);
    },
    [map, persist],
  );

  const removeForPoll = useCallback(
    async (accountId: string, pollId: bigint) => {
      const m = { ...(map[accountId] || {}) };
      delete m[String(pollId)];
      const next = { ...map, [accountId]: m };
      await persist(next);
    },
    [map, persist],
  );

  const exportJson = useCallback(() => {
    const blob = new Blob([JSON.stringify(map, replacer, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "revo-keys.json";
    a.click();
  }, [map]);

  const exportRevo = useCallback((accountId: string, filename?: string) => {
    const payload = map[accountId] || {};
    const blob = new Blob([JSON.stringify(payload, replacer, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename ?? `revo-keys-${accountId.slice(0, 8)}.json`;
    a.click();
  }, [map]);

  return (
    <RevoKeysContext.Provider
      value={{
        loaded,
        map,
        reload,
        getForPoll,
        generateForPoll,
        setForPoll,
        removeForPoll,
        exportJson,
        exportRevo,
      }}
    >
      {children}
    </RevoKeysContext.Provider>
  );
};

export function useRevoKeysCtx() {
  const c = useContext(RevoKeysContext);
  if (!c) throw new Error("RevoKeysProvider missing");
  return c;
}

type LeafData = {
  choice: bigint;
  revotingKey: [bigint, bigint];
  hash: bigint;
};

type TallyStore = {
  pollId: bigint;
  accountId: string;
  processedAfterId: bigint;
  processedCount: number;
  rootHex: string;
  runningMsgHashHex: string;
  tallyHashHex: string;
  tallySaltHex: string;
  tallyCounts: string[]; // decimal strings
  leaves: Record<string, LeafData>;
};

async function loadTallyStore(
  pollId: bigint,
  accountId: string,
): Promise<TallyStore | null> {
  const x = await idbGet(TALLY_DB_KEY(pollId, accountId));
  return (x as TallyStore) ?? null;
}

async function saveTallyStore(s: TallyStore): Promise<void> {
  await idbSet(TALLY_DB_KEY(s.pollId, s.accountId), s);
}

async function resetTallyStore(
  pollId: bigint,
  accountId: string,
): Promise<void> {
  await idbDel(TALLY_DB_KEY(pollId, accountId));
}

const KEYRING_DB_KEY = "anonvote:keyring:v1";
const ACTIVE_IDX_KEY = "anonvote:keyring:active:v1";
const REVO_DB_KEY = "anonvote:revo:v1";
const TALLY_DB_KEY = (pollId: bigint, accountId: string) =>
  `anonvote:tally:v1:${pollId}:${accountId}`;

function arraysEqual(arr1: Uint8Array, arr2: Uint8Array): boolean {
  if (arr1.length !== arr2.length) {
    return false;
  }
  return arr1.every((value, index) => value === arr2[index]);
}

function useKeyring() {
  const [locked, setLocked] = useState(true);
  const [pass, setPass] = useState("");
  const [accounts, setAccounts] = useState<BabyJubKeypair[]>([]);
  const [active, setActive_] = useState<number>(0);
  const [hasKeyring, setHasKeyring] = useState<boolean | null>(null);
  const [importStatus, setImportStatus] = useState<
    null | { ok: boolean; msg: string }
  >(null);

  const clearImportStatus = useCallback(() => setImportStatus(null), []);

  const setActive = useCallback((idx: number) => {
    setActive_(idx);
    try {
      localStorage.setItem(ACTIVE_IDX_KEY, String(idx));
    } catch {}
  }, []);

  useEffect(() => {
    (async () => {
      const blob = (await idbGet(KEYRING_DB_KEY)) as
        | EncryptedKeyringBlob
        | undefined;
      setHasKeyring(!!blob);
    })();
  }, []);

  const unlock = useCallback(async () => {
    const blob = (await idbGet(KEYRING_DB_KEY)) as
      | EncryptedKeyringBlob
      | undefined;
    if (!blob) {
      const firstBlob = await encryptToBlob(pass, [] as BabyJubKeypair[]);
      await idbSet(KEYRING_DB_KEY, firstBlob);
      setAccounts([]);
      setLocked(false);
      setHasKeyring(true);
      setActive(0);
      return true;
    }
    try {
      const accs = await decryptFromBlob<BabyJubKeypair[]>(pass, blob);
      setAccounts(accs);
      setLocked(false);
      try {
        const saved = Number(localStorage.getItem(ACTIVE_IDX_KEY) ?? "0") || 0;
        setActive(Math.min(Math.max(0, saved), Math.max(0, accs.length - 1)));
      } catch {
        setActive(0);
      }
      return true;
    } catch (e: any) {
      alert("Wrong passphrase or corrupted keyring");
      console.error(e);
      return false;
    }
  }, [pass]);

  const persist = useCallback(async (next: BabyJubKeypair[]) => {
    const blob = await encryptToBlob(pass, next);
    await idbSet(KEYRING_DB_KEY, blob);
    setAccounts(next);
  }, [pass]);

  const addNew = useCallback(async (name: string) => {
    const k = await genBabyJubKeypair_(name);
    await persist([...accounts, k]);
  }, [accounts, persist]);

  const importPrv = useCallback(async (name: string, prvHex: string) => {
    setImportStatus(null);

    let hex = prvHex.trim().toLowerCase();
    if (name.length == 0) {
      setImportStatus({ ok: false, msg: "Name should not be empty." });
      return;
    }
    if (hex.startsWith("0x")) hex = hex.slice(2);
    if (!/^[0-9a-f]+$/.test(hex)) {
      setImportStatus({ ok: false, msg: "Invalid hex." });
      return;
    }
    if (hex.length > 64 || hex.length < 1) {
      setImportStatus({
        ok: false,
        msg: "Private key must fit in 32 bytes (64 hex chars).",
      });
      return;
    }
    if (accounts.some((a) => a.name === name)) {
      setImportStatus({
        ok: false,
        msg: `An account named “${name}” already exists.`,
      });
      return;
    }

    const eddsa = await getEddsa();
    const babyjub = await getBabyjub();
    const F = babyjub.F;
    const prv = hexToBytes32(hex);

    if (accounts.some((a) => arraysEqual(a.prv, prv))) {
      setImportStatus({
        ok: false,
        msg: `An account with this private key already exists.`,
      });
      return;
    }

    const sk = prv2sk(prv, eddsa);
    const pub = babyjub.mulPointEscalar(babyjub.Base8, sk);
    const k: BabyJubKeypair = {
      name,
      prv,
      sk,
      pub: [F.toObject(pub[0]), F.toObject(pub[1])],
      createdAt: Date.now(),
    };
    await persist([...accounts, k]);
    setImportStatus({ ok: true, msg: `Imported “${name}” successfully.` });
  }, [accounts, persist]);

  const removeAt = useCallback(async (idx: number) => {
    const a = accounts[idx];
    const ok = confirm(
      `Delete key "${a.name}"?\n\n` +
        `This will also orphan any re-voting keys associated with it.\n` +
        `You may lose the ability to vote in polls tied to this key.\n\n` +
        `This action cannot be undone.`,
    );
    if (!ok) return;
    const next = accounts.slice();
    next.splice(idx, 1);
    await persist(next);
    if (active >= next.length) setActive(Math.max(0, next.length - 1));
  }, [accounts, active, persist, setActive]);

  const exportJson = useCallback(() => {
    const blob = new Blob([JSON.stringify(accounts, replacer, 2)], {
      type: "application/json",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "babyjub-keyring.json";
    a.click();
  }, [accounts]);

  return {
    locked,
    pass,
    setPass,
    unlock,
    hasKeyring,
    accounts,
    addNew,
    importPrv,
    importStatus,
    clearImportStatus,
    removeAt,
    active,
    setActive,
    exportJson,
  };
}

type KeyringApi = ReturnType<typeof useKeyring>;

const KeyringCtx = createContext<KeyringApi | null>(null);

export const useKeyringCtx = () => {
  const ctx = useContext(KeyringCtx);
  if (!ctx) {
    throw new Error("useKeyringCtx must be used within <KeyringProvider>");
  }
  return ctx;
};

const KeyringProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const kr = useKeyring();
  return <KeyringCtx.Provider value={kr}>{children}</KeyringCtx.Provider>;
};

async function getIrysForBrowserSolana(
  wallet: any,
  options?: { devnet?: boolean; rpc?: string },
): Promise<BaseWebIrys> {
  let irys = WebUploader(WebSolana).withProvider(wallet);
  if (options?.rpc) irys = irys.withRpc(options.rpc);
  if (options?.devnet) irys = irys.devnet();
  return await irys;
}

type IrysData = {
  data: Buffer;
  contentType: string;
  tags?: Array<{ name: string; value: string }>;
};

async function irysBatchUpload(
  wallet: any,
  data: IrysData[],
  opts?: { devnet?: boolean; rpc?: string },
): Promise<string[]> {
  if (data.length === 0) return [];
  const irys = await getIrysForBrowserSolana(wallet, {
    devnet: opts?.devnet,
    rpc: opts?.rpc,
  });
  const total = data.reduce((sum, d) => sum + d.data.byteLength, 0);
  const price = await irys.getPrice(total);
  await irys.fund(price);
  const urls: string[] = [];
  for (const item of data) {
    const resp = await irys.upload(item.data, {
      tags: [
        { name: "Content-Type", value: item.contentType },
        ...(item.tags || []),
      ],
    });
    urls.push(`https://gateway.irys.xyz/${resp.id}`);
  }
  return urls;
}

type ParsedCensus = {
  leaves: bigint[];
  labels?: Array<
    {
      i: number;
      pkX?: string;
      pkY?: string;
      label?: string;
      labelHash?: string;
    }
  >;
};

async function parseUploadedCensus(buf: Uint8Array): Promise<ParsedCensus> {
  if (buf.length % 32 !== 0) {
    throw new Error("census.bin must be multiple of 32 bytes");
  }
  const leaves: bigint[] = [];
  for (let i = 0; i < buf.length; i += 32) leaves.push(bytes32ToBig(buf, i));
  return { leaves };
}

let poseidonP: Poseidon | null = null;

async function getPoseidon(): Promise<Poseidon> {
  if (!poseidonP) poseidonP = await buildPoseidon();
  return poseidonP;
}

let babyjubP: BabyJub | null = null;

async function getBabyjub(): Promise<BabyJub> {
  if (!babyjubP) babyjubP = await buildBabyjub();
  return babyjubP;
}

let eddsaP: Eddsa | null = null;

async function getEddsa(): Promise<Eddsa> {
  if (!eddsaP) eddsaP = await buildEddsa();
  return eddsaP;
}

async function keyToLeafHex([x, y]: [bigint, bigint]): Promise<string> {
  const P = await getPoseidon();
  const F = P.F;
  const leaf = F.toObject(P([x, y]));
  return Array.from(toBytes32(leaf)).map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

const HEX = /^0x?[0-9a-fA-F]*$/;

const schemaBase = z.object({
  pollId: z.string().regex(/^\d+$/, "Digits only"),
  title: z.string().min(1, "Title is required").max(200, "Keep it short"),
  choices: z.array(z.object({ value: z.string().min(1, "Required") }))
    .min(1, "At least one choice").max(
      MAX_CHOICES,
      `Max ${MAX_CHOICES} choices`,
    ),
  coordMode: z.enum(["active", "manual"]),
  coordX: z.string().optional(),
  coordY: z.string().optional(),
  start: z.string().min(1, "Start required"),
  end: z.string().min(1, "End required"),
  feeLamports: z.string().regex(/^\d+$/, "Integer lamports"),
  censusBytes: z.instanceof(Uint8Array, { message: "Upload census .bin" }),
  censusCount: z.number().int().positive("Census empty"),
  censusRootHex: z.string().regex(/^0x[0-9a-fA-F]{64}$/, "Invalid root"),
}).superRefine((d, ctx) => {
  const startMs = Date.parse(d.start);
  const endMs = Date.parse(d.end);
  if (Number.isNaN(startMs) || Number.isNaN(endMs)) {
    ctx.addIssue({ code: "custom", message: "Invalid date", path: ["end"] });
    return;
  }
  if (endMs <= startMs) {
    ctx.addIssue({
      code: "custom",
      message: "End must be after start",
      path: ["end"],
    });
    return;
  }
  if (CLUSTER == "devnet") {
    // This ensures availability of census on Irys devnet.
    const limit = Date.now() + 60 * ONE_DAY_MS;
    if (endMs > limit) {
      ctx.addIssue({
        code: "custom",
        message: "On devnet, polls must end within 60 days from now.",
        path: ["end"],
      });
    }
  } else {
    if (endMs - startMs > MAX_POLL_DURATION * 1000) {
      ctx.addIssue({
        code: "custom",
        message: "Poll duration must be ≤ 365 days.",
        path: ["end"],
      });
    }
  }
});

const schema = z.discriminatedUnion("coordMode", [
  schemaBase.safeExtend({
    coordMode: z.literal("active"),
  }),
  schemaBase.safeExtend({
    coordMode: z.literal("manual"),
    coordX: z.string().regex(HEX, "32-byte hex"),
    coordY: z.string().regex(HEX, "32-byte hex"),
  }),
]);

type FormValues = z.infer<typeof schema>;
type Stage =
  | "idle"
  | "uploading data to Irys"
  | "creating poll"
  | "done"
  | "error";

const ActiveCoordinatorSummary: React.FC = () => {
  const KR = useKeyringCtx();
  const acc = KR.accounts[KR.active];
  if (!acc) {
    return (
      <div className="text-xs text-amber-600">
        No active ZK account. Open “ZK Accounts” and create/select one.
      </div>
    );
  }
  const pkx = "0x" + acc.pub[0].toString(16).padStart(64, "0");
  const pky = "0x" + acc.pub[1].toString(16).padStart(64, "0");
  return (
    <div className="rounded-lg border p-2 bg-gray-50 dark:bg-zinc-800/50 text-xs">
      Using account: <span className="font-medium">{acc.name}</span>
      <div className="font-mono break-all mt-1">X: {pkx}</div>
      <div className="font-mono break-all">Y: {pky}</div>
    </div>
  );
};

const btn = (enabled: boolean) =>
  `px-4 py-2 rounded-lg text-white ${
    enabled ? "bg-black hover:bg-neutral-800" : "bg-gray-400 cursor-not-allowed"
  }`;

const PollCreator: React.FC<{}> = () => {
  const wallet = useWallet();
  const KR = useKeyringCtx();
  const connection = new Connection(RPC_URL, { commitment: "confirmed" });

  useEffect(() => {
    if (!wallet.publicKey || !connection) return;
    const provider = new anchor.AnchorProvider(
      connection,
      wallet as any,
      anchor.AnchorProvider.defaultOptions(),
    );
    setAnonProvider(provider);
  }, [wallet.publicKey, connection]);

  const {
    control,
    register,
    handleSubmit,
    setValue,
    watch,
    trigger,
    formState: { errors, isValid, isSubmitting },
  } = useForm<FormValues>({
    mode: "onChange",
    resolver: zodResolver(schema),
    defaultValues: {
      pollId: String(
        (crypto.getRandomValues(new Uint32Array(1))[0] % 100_000_000_000_000) ||
          1,
      ),
      title: "",
      choices: [{ value: "" }, { value: "" }],
      coordMode: "active",
      coordX: undefined,
      coordY: undefined,
      start: toLocalInputValue(new Date(Date.now() + 60_000)),
      end: toLocalInputValue(new Date(Date.now() + 3_600_000)),
      feeLamports: "0",
      censusBytes: undefined,
      censusCount: 0,
      censusRootHex: "0x" + "0".repeat(64),
    },
  });
  const coordMode = watch("coordMode");

  const { fields, append, remove } = useFieldArray({
    control,
    name: "choices",
  });
  const [stage, setStage] = useState<Stage>("idle");
  const [errMsg, setErrMsg] = useState("");

  const onSubmit = async (data: FormValues) => {
    try {
      setErrMsg("");
      setStage("uploading data to Irys");

      const cleanedChoices = data.choices.map((c) => c.value.trim()).filter((
        c,
      ) => c.length > 0);
      const descJson = JSON.stringify({
        title: data.title.trim(),
        choices: cleanedChoices,
      });
      const descBytes = new TextEncoder().encode(descJson);

      const [descUrl, censusUrl] = await irysBatchUpload(
        wallet,
        [
          { data: Buffer.from(descBytes), contentType: "application/json" },
          {
            data: Buffer.from(data.censusBytes),
            contentType: "application/octet-stream",
            tags: [{ name: "App-Name", value: "anon-vote-census" }, {
              name: "Leaves",
              value: String(data.censusCount),
            }],
          },
        ],
        { devnet: CLUSTER === "devnet", rpc: RPC_URL },
      );

      setStage("creating poll");

      const id = BigInt(data.pollId);
      const start = localInputToUnixSeconds(data.start);
      const end = localInputToUnixSeconds(data.end);
      const fee = BigInt(data.feeLamports);

      let coordinatorKey: { x: number[]; y: number[] };
      if (data.coordMode === "active") {
        const acc = KR.accounts[KR.active];
        if (!acc) throw new Error("No active ZK account selected");
        const [px, py] = acc.pub;
        coordinatorKey = {
          x: Array.from(toBytes32(px)),
          y: Array.from(toBytes32(py)),
        };
      } else {
        coordinatorKey = {
          x: Array.from(hexToBytes32(data.coordX!)),
          y: Array.from(hexToBytes32(data.coordY!)),
        };
      }

      const ix: InstructionWithCu = await createPoll({
        payer: wallet.publicKey!,
        id,
        censusRoot: Array.from(hexToBytes32(data.censusRootHex)),
        coordinatorKey,
        nChoices: cleanedChoices.length,
        votingStartTime: new anchor.BN(start),
        votingEndTime: new anchor.BN(end),
        fee,
        feeDestination: wallet.publicKey!,
        nVoters: BigInt(data.censusCount!),
        descriptionUrl: descUrl,
        censusUrl: censusUrl,
      });

      const tx = new Transaction().add(
        cuLimitInstruction([ix]),
        ...[ix].map((x) => x.instruction),
      );
      tx.recentBlockhash = (await connection!.getLatestBlockhash()).blockhash;
      tx.feePayer = wallet.publicKey!;

      await wallet.sendTransaction(tx, connection!, { maxRetries: 3 });

      setStage("done");
    } catch (e: any) {
      console.error(e);
      setErrMsg("Error: " + String(e?.message || e));
      setStage("error");
    }
  };

  const onCensusFile = async (f: File) => {
    const bytes = new Uint8Array(await f.arrayBuffer());
    const { leaves } = await parseUploadedCensus(bytes);
    const root = await getMerkleRoot(CENSUS_DEPTH, leaves);
    setValue("censusBytes", bytes, { shouldValidate: true });
    setValue("censusCount", leaves.length, { shouldValidate: true });
    setValue("censusRootHex", toHex32(root), { shouldValidate: true });

    /// XXX: Otherwise it won't show date errors until census is uploaded
    // and date is changed again...
    await trigger(["start", "end"]);
  };

  const inputCN = "w-full rounded border px-3 py-2 " +
    "border-gray-300 focus:outline-none focus:ring-2 focus:ring-black/20 " +
    "dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100 placeholder-neutral-400";

  const disabled = isSubmitting || !isValid || !wallet.publicKey ||
    (stage !== "idle" && stage !== "done" && stage !== "error") ||
    (coordMode === "active" && !KR.accounts[KR.active]);
  return (
    <form
      onSubmit={handleSubmit(onSubmit)}
      className="max-w-3xl mx-auto p-4 rounded-2xl border bg-white border-gray-200 dark:bg-neutral-900 dark:border-neutral-800"
    >
      <h2 className="text-xl font-semibold mb-3">Create Poll</h2>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="space-y-3">
          <label className="block text-sm font-medium">Poll ID</label>
          <input className={inputCN} {...register("pollId")} />
          {errors.pollId && (
            <p className="text-red-500 text-xs">{errors.pollId.message}</p>
          )}

          <label className="block text-sm font-medium">Start</label>
          <input
            type="datetime-local"
            className={inputCN}
            {...register("start")}
          />
          {errors.start && (
            <p className="text-red-500 text-xs">{errors.start.message}</p>
          )}

          <label className="block text-sm font-medium">End</label>
          <input
            type="datetime-local"
            className={inputCN}
            {...register("end")}
          />
          {errors.end && (
            <p className="text-red-500 text-xs">{errors.end.message}</p>
          )}

          <div className="space-y-2">
            <label className="block text-sm font-medium">Tallier key</label>
            <div className="flex gap-3 items-center">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="radio"
                  value="active"
                  {...register("coordMode")}
                  defaultChecked
                />
                Use ZK account
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="radio" value="manual" {...register("coordMode")} />
                Enter manually
              </label>
            </div>
            {}
            {coordMode !== "manual" ? <ActiveCoordinatorSummary /> : (
              <div>
                <input
                  placeholder="0x… (X)"
                  className="w-full rounded border px-3 py-2 font-mono mb-2"
                  {...register("coordX")}
                />
                {errors.coordX && (
                  <p className="text-red-600 text-xs">
                    {errors.coordX.message}
                  </p>
                )}
                <input
                  placeholder="0x… (Y)"
                  className="w-full rounded border px-3 py-2 font-mono"
                  {...register("coordY")}
                />
                {errors.coordY && (
                  <p className="text-red-600 text-xs">
                    {errors.coordY.message}
                  </p>
                )}
              </div>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium">
              Poll fee (lamports)
            </label>
            <input
              placeholder="e.g. 200000"
              className={inputCN}
              {...register("feeLamports")}
            />
            {errors.feeLamports && (
              <p className="text-red-500 text-xs">
                {errors.feeLamports.message}
              </p>
            )}
          </div>
        </div>

        <div className="space-y-3">
          <label className="block text-sm font-medium">Poll title</label>
          <input className={inputCN} {...register("title")} />
          {errors.title && (
            <p className="text-red-500 text-xs">{errors.title.message}</p>
          )}

          <div className="flex items-center justify-between">
            <label className="text-sm font-medium">
              Choices (1–{MAX_CHOICES})
            </label>
            <button
              type="button"
              className="text-sm underline"
              onClick={() => append({ value: "" })}
              disabled={fields.length >= MAX_CHOICES}
            >
              + Add
            </button>
          </div>

          <div className="space-y-2">
            {fields.map((f, i) => (
              <div key={f.id} className="flex gap-2">
                <input
                  className={inputCN + " flex-1"}
                  {...register(`choices.${i}.value` as const)}
                  placeholder={`Choice #${i + 1}`}
                />
                <button
                  type="button"
                  className="px-2 rounded border dark:border-neutral-700"
                  onClick={() => remove(i)}
                  disabled={fields.length <= 1}
                >
                  Remove
                </button>
              </div>
            ))}
            {errors.choices && (
              <p className="text-red-500 text-xs">
                {errors.choices.message as string}
              </p>
            )}
          </div>

          <div className="mt-3">
            <div className="flex items-center gap-2">
              <label className="block text-sm font-medium">Census</label>
              <CensusHelp />
            </div>
            <input
              type="file"
              accept=".bin"
              onChange={(e) =>
                e.target.files && onCensusFile(e.target.files[0])}
              className={cn(
                "block w-full rounded border border-gray-300 dark:border-neutral-700",
                "bg-white dark:bg-neutral-800 text-sm text-neutral-900 dark:text-neutral-100",
                "file:mr-4 file:rounded-lg file:border file:border-gray-300 dark:file:border-neutral-700",
                "file:bg-white dark:file:bg-neutral-800 file:px-3 file:py-2 file:text-sm",
                "file:font-medium file:text-neutral-900 dark:file:text-neutral-100",
              )}
            />
            {errors.censusBytes && (
              <p className="text-red-500 text-xs">
                {errors.censusBytes.message}
              </p>
            )}
            {errors.censusCount && (
              <p className="text-red-500 text-xs">
                {errors.censusCount.message}
              </p>
            )}
            {errors.censusRootHex && (
              <p className="text-red-500 text-xs">
                {errors.censusRootHex.message}
              </p>
            )}
            <ComputedCensusHints control={control} />
          </div>
        </div>
      </div>

      <div className="mt-4 flex items-center gap-3">
        <button
          className={btn(!disabled)}
          disabled={disabled}
        >
          {isSubmitting ? "Working…" : "Create poll"}
        </button>
        {stage !== "idle" && (
          <span className="text-sm text-purple-600">{stage}</span>
        )}
      </div>

      {errMsg && (
        <div className="mt-3 text-sm text-red-500 whitespace-pre-wrap">
          {errMsg}
        </div>
      )}
    </form>
  );
};

const ComputedCensusHints = ({ control }: { control: any }) => {
  const values = control._formValues as FormValues;
  return (
    <div className="text-xs mt-1 text-neutral-600 dark:text-neutral-300">
      {values?.censusCount
        ? <div>Entry count: {values.censusCount}</div>
        : null}
    </div>
  );
};

const CensusHelp: React.FC = () => {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative inline-block">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-5 h-5 rounded-full text-xs font-bold flex items-center justify-center border border-gray-300 dark:border-neutral-600 hover:bg-neutral-100 dark:hover:bg-neutral-800"
        title="What is census.bin?"
      >
        ?
      </button>
      {open && (
        <div className="absolute z-10 mt-2 w-80 p-3 text-xs rounded-lg border bg-white dark:bg-neutral-900 border-gray-200 dark:border-neutral-800 shadow">
          <p className="mb-1 font-medium">Census file format</p>
          <ul className="list-disc ml-4 space-y-1">
            <li>Binary file, no header.</li>
            <li>
              Concatenation of leaves, one per voter, each exactly{" "}
              <b>32 bytes</b> (big-endian).
            </li>
            <li>
              Each leaf is <code>Poseidon(pubX, pubY)</code>{" "}
              over BabyJub, encoded as a field element (BE).
            </li>
            <li>No padding; file size must be divisible by 32.</li>
          </ul>
        </div>
      )}
    </div>
  );
};

const ZkAccountsButton: React.FC<{ onClick: () => void }> = ({ onClick }) => {
  const KR = useKeyringCtx();
  let label = "ZK Accounts";
  if (!KR.locked && KR.accounts.length) {
    const a = KR.accounts[KR.active] ?? KR.accounts[0];
    label = a.name;
  }
  return (
    <button
      type="button"
      className="rounded-lg border px-3 py-2 text-sm dark:border-neutral-700 hover:bg-neutral-100 dark:hover:bg-neutral-800"
      onClick={onClick}
    >
      {label}
    </button>
  );
};

const KeyringPanel: React.FC<{ open: boolean }> = ({ open }) => {
  const KR = useKeyringCtx();
  const [newName, setNewName] = useState("");
  const [importName, setImportName] = useState("");
  const [importPrv, setImportPrv] = useState("");
  const [confirmPass, setConfirmPass] = useState("");
  const creating = KR.hasKeyring === false;
  const RK = useRevoKeysCtx();

  useEffect(() => {
    if (!open) {
      KR.clearImportStatus();
      setNewName("");
      setImportName("");
      setImportPrv("");
    }
  }, [open, KR]);

  if (KR.locked) {
    return (
      <Card title={creating ? "Create ZK keyring" : "Unlock ZK keyring"}>
        <div className="space-y-2">
          <input
            type="password"
            value={KR.pass}
            onChange={(e) => KR.setPass(e.target.value)}
            placeholder={creating ? "Set passphrase" : "Passphrase"}
            className="w-full rounded border px-3 py-2 border-gray-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
          />
          {creating && (
            <input
              type="password"
              value={confirmPass}
              onChange={(e) => setConfirmPass(e.target.value)}
              placeholder="Confirm passphrase"
              className="w-full rounded border px-3 py-2 border-gray-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
            />
          )}
          <button
            onClick={async () => {
              if (creating) {
                if (!KR.pass || KR.pass.length < 4) {
                  alert("Use a passphrase at least 4 characters long.");
                  return;
                }
                if (KR.pass !== confirmPass) {
                  alert("Passphrases do not match.");
                  return;
                }
              }
              await KR.unlock();
            }}
            className="mt-1 rounded-lg px-4 py-2 bg-black text-white hover:bg-neutral-800"
          >
            {creating ? "Create keyring" : "Unlock"}
          </button>
          <p className="text-xs text-neutral-500 dark:text-neutral-400">
            {creating
              ? "This sets your keyring passphrase. It encrypts your ZK accounts with PBKDF2(AES-GCM) and stores them in your browser (IndexedDB). Keep it safe — it cannot be recovered."
              : "Keychain is encrypted and only stored in your browser."}
          </p>
        </div>
      </Card>
    );
  }

  return (
    <Card title="BabyJub accounts">
      <div className="flex gap-2 items-end">
        <div className="flex-1">
          <label className="block text-sm font-medium">Label</label>
          <input
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            className="w-full rounded border px-3 py-2 border-gray-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
          />
        </div>
        <button
          onClick={() => KR.addNew(newName || `acct-${KR.accounts.length + 1}`)}
          className="rounded-lg px-4 py-2 bg-black text-white hover:bg-neutral-800"
        >
          New
        </button>
        <button
          className="rounded-lg px-4 py-2 border dark:border-neutral-700"
          onClick={KR.exportJson}
        >
          Export
        </button>
      </div>

      <div className="mt-4 flex gap-2 items-end">
        <div className="flex-1">
          <label className="block text-sm font-medium">Import name</label>
          <input
            value={importName}
            onChange={(e) => setImportName(e.target.value)}
            className="w-full rounded border px-3 py-2 border-gray-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
          />
        </div>
        <div className="flex-[2]">
          <label className="block text-sm font-medium">
            Private seed (hex)
          </label>
          <input
            value={importPrv}
            onChange={(e) => setImportPrv(e.target.value)}
            className="w-full rounded border px-3 py-2 font-mono border-gray-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
          />
        </div>
        <button
          onClick={() => KR.importPrv(importName, importPrv)}
          className="rounded-lg px-4 py-2 border dark:border-neutral-700"
        >
          Import
        </button>
      </div>
      {KR.importStatus && (
        <div
          className={`mt-2 text-sm ${
            KR.importStatus.ok ? "text-emerald-600" : "text-red-600"
          }`}
        >
          {KR.importStatus.msg}
        </div>
      )}

      <div className="mt-4">
        {KR.accounts.length === 0 && (
          <p className="text-sm italic text-neutral-600 dark:text-neutral-300">
            No accounts yet.
          </p>
        )}
        <div className="space-y-2">
          {KR.accounts.map((a, i) => (
            <div
              key={i}
              className={cn(
                "rounded-xl border p-3 border-gray-200 dark:border-neutral-800",
                i === KR.active && "border-black dark:border-white",
              )}
            >
              <div className="flex items-center justify-between">
                <div className="font-medium">{a.name}</div>
                <div className="flex gap-2">
                  <button
                    className="text-xs underline"
                    onClick={() => KR.setActive(i)}
                  >
                    Use
                  </button>
                  <button
                    className="text-xs underline text-red-600"
                    onClick={() => KR.removeAt(i)}
                  >
                    Delete
                  </button>
                </div>
              </div>
              <div className="text-xs font-mono break-all mt-2">
                pkX: 0x{a.pub[0].toString(16)}
              </div>
              <div className="text-xs font-mono break-all">
                pkY: 0x{a.pub[1].toString(16)}
              </div>
              <details className="mt-1">
                <summary className="text-xs text-neutral-600 dark:text-neutral-400 cursor-pointer select-none">
                  show private key
                </summary>
                <div className="text-xs font-mono break-all">
                  prv: 0x{bytesToHex(a.prv)}
                </div>
              </details>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-6">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold">
            Re-voting keys{KR.accounts[KR.active]?.name
              ? ` for ${KR.accounts[KR.active]?.name}`
              : ""}
          </h3>
          <button
            className="text-xs underline"
            onClick={() => {
              const acct = KR.accounts[KR.active];
              if (!acct) return;
              const id = idForAccount(acct);
              RK.exportRevo(id, `revo-keys-${acct.name}.json`);
            }}
            disabled={!RK.loaded || !KR.accounts[KR.active]}
            title="Export this account's re-voting keys as JSON"
          >
            Export
          </button>
        </div>
        {!RK.loaded
          ? <div className="text-sm opacity-70 mt-2">Loading…</div>
          : (
            <div className="mt-2">
              {(() => {
                const acct = KR.accounts[KR.active];
                if (!acct) {
                  return (
                    <div className="text-sm opacity-70">No active account.</div>
                  );
                }
                const accountId = idForAccount(acct);
                const entries = Object.entries(RK.map[accountId] || {}).sort(
                  (a, b) => {
                    if (a[0] > b[0]) {
                      return 1;
                    } else if (a < b) {
                      return -1;
                    } else {
                      return 0;
                    }
                  },
                );
                if (entries.length === 0) {
                  return (
                    <div className="text-sm opacity-70">No re-voting keys.</div>
                  );
                }
                return (
                  <div className="space-y-2">
                    {entries.map(([pollId, k]) => (
                      <div key={pollId} className="rounded-lg border p-3">
                        <div className="flex items-center justify-between">
                          <div className="font-medium truncate">
                            {k.title ?? "Untitled poll"}
                          </div>
                          <div className="text-xs opacity-70 ml-2 shrink-0">
                            #{pollId}
                          </div>
                        </div>
                        <div className="text-xs font-mono break-all mt-2">
                          pkX: 0x{k.pub[0].toString(16)}
                        </div>
                        <div className="text-xs font-mono break-all">
                          pkY: 0x{k.pub[1].toString(16)}
                        </div>
                        <details className="mt-1">
                          <summary className="text-xs text-gray-600 cursor-pointer select-none">
                            show private key
                          </summary>
                          <div className="text-xs font-mono break-all">
                            prv: 0x{bytesToHex(k.prv)}
                          </div>
                        </details>
                        <div className="mt-2 flex gap-2">
                          <RevoDeleteButton
                            accountId={accountId}
                            pollId={BigInt(pollId)}
                            title={k.title}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                );
              })()}
            </div>
          )}
      </div>
    </Card>
  );
};

const RevoDeleteButton: React.FC<
  { accountId: string; pollId: bigint; title: string }
> = ({ accountId, pollId, title }) => {
  const RK = useRevoKeysCtx();
  const onClick = async () => {
    const ok = confirm(
      `Delete re-voting key for poll #${pollId} (${title})?\n\n` +
        `If you delete this key, you may be unable to re-vote in this poll.\n\n` +
        `This action cannot be undone.`,
    );
    if (!ok) return;
    await RK.removeForPoll(accountId, BigInt(pollId));
  };
  return (
    <button
      className="rounded-lg px-3 py-1 border text-xs text-red-600"
      onClick={onClick}
      title="Delete this re-voting key"
    >
      Delete
    </button>
  );
};

const AccountDrawer: React.FC<{ open: boolean; onClose: () => void }> = (
  { open, onClose },
) => {
  return (
    <div
      className={cn(
        "fixed inset-0 z-50 transition",
        open ? "pointer-events-auto" : "pointer-events-none",
      )}
    >
      {/* backdrop */}
      <div
        onClick={onClose}
        className={cn(
          "absolute inset-0 bg-black/40 transition-opacity",
          open ? "opacity-100" : "opacity-0",
        )}
      />
      {/* panel */}
      <div
        className={cn(
          "absolute right-0 top-0 h-full w-full max-w-md",
          "bg-white dark:bg-neutral-900 border-l border-gray-200 dark:border-neutral-800",
          "shadow-xl transform transition-transform",
          open ? "translate-x-0" : "translate-x-full",
        )}
      >
        <div className="p-4 flex items-center justify-between border-b border-gray-200 dark:border-neutral-800">
          <h3 className="text-lg font-semibold">ZK Accounts</h3>
          <button
            className="rounded px-2 py-1 border dark:border-neutral-700"
            onClick={onClose}
          >
            ✕
          </button>
        </div>
        <div className="p-4 overflow-y-auto h-[calc(100%-56px)]">
          <KeyringPanel open={open} />
        </div>
      </div>
    </div>
  );
};

const ResultsBars: React.FC<{
  title: string;
  choices: string[];
  tally: number[];
}> = ({ title, choices, tally }) => {
  const data = useMemo(() => {
    const pairs = choices.map((label, i) => ({
      label,
      count: tally[i] ?? 0,
      idx: i,
    }));
    pairs.sort((a, b) => (b.count - a.count) || (a.idx - b.idx));
    const total = Math.max(0, pairs.reduce((s, x) => s + x.count, 0));
    const max = Math.max(1, ...pairs.map((p) => p.count));
    return { pairs, total, max };
  }, [choices, tally]);

  return (
    <Card title={title}>
      {data.total === 0
        ? (
          <div className="text-sm text-gray-600 dark:text-zinc-300">
            No votes yet.
          </div>
        )
        : (
          <div className="space-y-3">
            {data.pairs.map((p) => {
              const pct = data.total === 0
                ? 0
                : Math.round((p.count / data.total) * 100);
              const rel = Math.round((p.count / data.max) * 100);
              return (
                <div key={p.idx}>
                  <div className="flex items-baseline justify-between gap-3">
                    <div className="font-medium truncate">{p.label}</div>
                    <div className="text-xs tabular-nums text-gray-600 dark:text-zinc-300">
                      {p.count} ({pct}%)
                    </div>
                  </div>
                  <div className="h-2 w-full bg-gray-200 dark:bg-zinc-800 rounded overflow-hidden">
                    <div
                      className="h-full bg-emerald-600 dark:bg-emerald-500 transition-[width] duration-300"
                      style={{ width: `${rel}%` }}
                    />
                  </div>
                </div>
              );
            })}
            <div className="text-xs text-gray-500 dark:text-zinc-400">
              Total votes: <span className="tabular-nums">{data.total}</span>
            </div>
          </div>
        )}
    </Card>
  );
};

type PollItem = {
  poll_id: string;
  voting_start_time: number;
  voting_end_time: number;
  title: string;
  choices: string[];
};

type PollDetail = {
  poll_id: string;
  census_root: string;
  coordinator_key: [string, string];
  voting_start_time: number;
  voting_end_time: number;
  fee: string;
  platform_fee: string;
  fee_destination: string;
  description_url: string;
  census_url: string;
  tally: number[] | null;
  title: string;
  choices: string[];
};

type PollPage = { items: PollItem[]; total: number };
const POLL_PAGE_LIMIT = 20;

function formatDiff(ms: number): string {
  const s = Math.max(1, Math.floor(ms / 1000));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function pollStatus(nowMs: number, startSec: number, endSec: number): string {
  const startMs = startSec * 1000;
  const endMs = endSec * 1000;
  if (nowMs < startMs) return `Starts in ${formatDiff(startMs - nowMs)}`;
  if (nowMs < endMs) return `Ends in ${formatDiff(endMs - nowMs)}`;
  return `Ended ${formatDiff(nowMs - endMs)} ago`;
}

function pollStatusMeta(
  nowMs: number,
  startSec: number,
  endSec: number,
): { label: string; cls: string } {
  const label = pollStatus(nowMs, startSec, endSec);
  const startMs = startSec * 1000;
  const endMs = endSec * 1000;
  if (nowMs < startMs) {
    return {
      label,
      cls: "bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300",
    };
  } else if (nowMs < endMs) {
    return {
      label,
      cls:
        "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300",
    };
  } else {
    return {
      label,
      cls:
        "bg-neutral-100 text-neutral-600 dark:bg-neutral-800/60 dark:text-neutral-400",
    };
  }
}

const PollRow: React.FC<{ p: PollItem; to?: string }> = ({ p, to }) => {
  const now = Date.now();
  const meta = pollStatusMeta(now, p.voting_start_time, p.voting_end_time);
  return (
    <Link
      to={to ?? `/poll/${p.poll_id}`}
      className="block rounded-xl border p-3 border-gray-200 dark:border-neutral-800
                  hover:bg-neutral-50 dark:hover:bg-neutral-800 transition"
    >
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="font-medium truncate">
            {p.title || "Untitled poll"}
          </div>
          <div className="mt-1 flex items-center gap-2 text-xs">
            <span className="opacity-70">#{p.poll_id}</span>
            <span
              className={`inline-flex items-center px-2 py-0.5 rounded ${meta.cls}`}
            >
              {meta.label}
            </span>
          </div>
        </div>
        <div className="shrink-0 text-neutral-400 group-hover:text-neutral-600 dark:group-hover:text-neutral-300 hidden sm:block">
          →
        </div>
      </div>
    </Link>
  );
};

const MyVoterPolls: React.FC = () => {
  const KR = useKeyringCtx();
  const [leafHex, setLeafHex] = useState<string>("");
  const [page, setPage] = useState<PollPage | null>(null);
  const [after, setAfter] = useState<number>(0);
  const [stack, setStack] = useState<number[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    (async () => {
      const acc = KR.accounts[KR.active] ?? KR.accounts[0];
      if (!acc) return;
      const leaf = await keyToLeafHex(acc.pub);
      setLeafHex(leaf);
      setAfter(0);
      setStack([]);
    })();
  }, [KR.accounts, KR.active]);

  useEffect(() => {
    if (!leafHex) return;
    (async () => {
      setLoading(true);
      try {
        const url = new URL(`${INDEXER_URL}/voters/${leafHex}/polls`);
        if (after) url.searchParams.set("after", String(after));
        url.searchParams.set("limit", String(POLL_PAGE_LIMIT));
        const r = await fetch(url.toString());
        if (!r.ok) {
          throw new Error(await r.text());
        }
        const j: PollPage = await r.json();
        setPage(j);
      } catch (e: any) {
        console.error(e);
        setErr("Error: " + String(e?.message || e));
      } finally {
        setLoading(false);
      }
    })();
  }, [leafHex, after]);

  const next = () => {
    if (!page || page.total <= after + POLL_PAGE_LIMIT) return;
    setStack((s) => [...s, after]);
    setAfter(after + POLL_PAGE_LIMIT);
  };
  const prev = () => {
    if (stack.length === 0) return;
    const s = stack.slice();
    const a = s.pop()!;
    setStack(s);
    setAfter(a);
  };

  return (
    <Card title="Vote">
      {KR.locked
        ? (
          <p className="text-sm text-amber-600">
            Unlock your ZK keyring (see “ZK Accounts”) to view polls for your
            active key.
          </p>
        )
        : (
          <>
            {!page && loading && (
              <div className="text-sm opacity-70">Loading…</div>
            )}
            {!page && err && <div className="text-sm text-red-600">{err}</div>}
            {page && page.items.length === 0 && (
              <div className="text-sm opacity-70">No polls found.</div>
            )}
            <div className="space-y-2">
              {page?.items.map((p) => <PollRow key={p.poll_id} p={p} />)}
            </div>
            <div className="mt-3 flex gap-2 justify-end">
              <button
                className={`rounded-lg px-3 py-2 border dark:border-neutral-700 ${
                  stack.length === 0 || loading
                    ? "opacity-50 cursor-not-allowed"
                    : "hover:bg-neutral-100 dark:hover:bg-neutral-800"
                }`}
                onClick={prev}
                disabled={loading || stack.length === 0}
                aria-label="Previous page"
              >
                ‹
              </button>
              <button
                className={`rounded-lg px-3 py-2 border dark:border-neutral-700 ${
                  (!page || page.total <= after + POLL_PAGE_LIMIT || loading)
                    ? "opacity-50 cursor-not-allowed"
                    : "hover:bg-neutral-100 dark:hover:bg-neutral-800"
                }`}
                onClick={next}
                disabled={loading || !page ||
                  page.total <= after + POLL_PAGE_LIMIT}
                aria-label="Next page"
              >
                ›
              </button>
            </div>
          </>
        )}
    </Card>
  );
};

const MyCoordinatorPolls: React.FC = () => {
  const KR = useKeyringCtx();
  const [xyHex, setXyHex] = useState<string>("");
  const [page, setPage] = useState<PollPage | null>(null);
  const [after, setAfter] = useState<number>(0);
  const [stack, setStack] = useState<number[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    const acc = KR.accounts[KR.active] ?? KR.accounts[0];
    if (!acc) return;
    setXyHex(
      (acc.pub[0].toString(16).padStart(64, "0") +
        acc.pub[1].toString(16).padStart(64, "0")).toLowerCase(),
    );
    setAfter(0);
    setStack([]);
  }, [KR.accounts, KR.active]);

  useEffect(() => {
    if (!xyHex) return;
    (async () => {
      setLoading(true);
      try {
        const url = new URL(`${INDEXER_URL}/coordinators/${xyHex}/polls`);
        if (after) url.searchParams.set("after", String(after));
        url.searchParams.set("limit", "20");
        const r = await fetch(url.toString());
        if (!r.ok) {
          throw new Error(await r.text());
        }
        const j: PollPage = await r.json();
        setPage(j);
      } catch (e: any) {
        console.error(e);
        setErr("Error: " + String(e?.message || e));
      } finally {
        setLoading(false);
      }
    })();
  }, [xyHex, after]);

  const next = () => {
    if (!page || page.total <= after + POLL_PAGE_LIMIT) return;
    setStack((s) => [...s, after]);
    setAfter(after + POLL_PAGE_LIMIT);
  };
  const prev = () => {
    if (stack.length === 0) return;
    const s = stack.slice();
    const a = s.pop()!;
    setStack(s);
    setAfter(a);
  };

  return (
    <Card title="Tally">
      {KR.locked
        ? (
          <p className="text-sm text-amber-600">
            Unlock your ZK keyring (see “ZK Accounts”) to view polls coordinated
            by your active key.
          </p>
        )
        : (
          <>
            {!page && loading && (
              <div className="text-sm opacity-70">Loading…</div>
            )}
            {!page && err && <div className="text-sm text-red-600">{err}</div>}
            {page && page.items.length === 0 && (
              <div className="text-sm opacity-70">No polls found.</div>
            )}
            <div className="space-y-2">
              {page?.items.map((p) => (
                <PollRow key={p.poll_id} p={p} to={`/tally/${p.poll_id}`} />
              ))}
            </div>
            <div className="mt-3 flex gap-2 justify-end">
              <button
                className={`rounded-lg px-3 py-2 border dark:border-neutral-700 ${
                  stack.length === 0 || loading
                    ? "opacity-50 cursor-not-allowed"
                    : "hover:bg-neutral-100 dark:hover:bg-neutral-800"
                }`}
                onClick={prev}
                disabled={loading || stack.length === 0}
                aria-label="Previous page"
              >
                ‹
              </button>
              <button
                className={`rounded-lg px-3 py-2 border dark:border-neutral-700 ${
                  (!page || page.total <= after + POLL_PAGE_LIMIT || loading)
                    ? "opacity-50 cursor-not-allowed"
                    : "hover:bg-neutral-100 dark:hover:bg-neutral-800"
                }`}
                onClick={next}
                disabled={loading || !page ||
                  page.total <= after + POLL_PAGE_LIMIT}
                aria-label="Next page"
              >
                ›
              </button>
            </div>
          </>
        )}
    </Card>
  );
};

function toLocalInputValue(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${
    p(d.getHours())
  }:${p(d.getMinutes())}`;
}

function localInputToUnixSeconds(s: string): number {
  const [date, time] = s.split("T");
  const [y, m, dd] = date.split("-").map(Number);
  const [hh, mm] = time.split(":").map(Number);
  return Math.floor(
    new Date(y, (m || 1) - 1, dd || 1, hh || 0, mm || 0, 0, 0).getTime() / 1000,
  );
}

const VotePage: React.FC<{ pollId: bigint }> = ({ pollId }) => {
  const wallet = useWallet();
  const KR = useKeyringCtx();
  const RK = useRevoKeysCtx();
  const connection = new Connection(RPC_URL, { commitment: "confirmed" });
  const [poll, setPoll] = useState<PollDetail | null>(null);
  const [title, setTitle] = useState<string>("Loading…");
  const [choices, setChoices] = useState<string[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [stage, setStage] = useState<string>("");
  const [err, setErr] = useState<string>("");
  const [busy, setBusy] = useState(false);

  const clock = usePollClock(
    poll?.voting_start_time ?? 0,
    poll?.voting_end_time ?? 0,
  );

  useEffect(() => {
    (async () => {
      setErr("");
      setStage("Loading poll…");
      const r = await fetch(`${INDEXER_URL}/polls/${pollId}`);
      if (!r.ok) {
        setErr("Poll not found");
        setStage("");
        return;
      }
      const j: PollDetail = await r.json();
      setPoll(j);
      if (j.title && j.choices) {
        setTitle(j.title);
        setChoices(j.choices);
      } else {
        try {
          const d = await fetch(j.description_url).then((x) => x.json());
          setTitle(d?.title || "Untitled poll");
          setChoices(Array.isArray(d?.choices) ? d.choices.map(String) : []);
        } catch {
          setTitle("Untitled poll");
          setChoices([]);
        }
      }
      setStage("");
    })().catch((e) => {
      setErr("Error: " + String(e));
      setStage("");
    });
  }, [pollId]);

  const disabled = busy || !wallet.publicKey || KR.locked || !poll ||
    selected == null || Date.now() / 1000 < poll.voting_start_time ||
    Date.now() / 1000 > poll.voting_end_time;

  const onVoteClick = async () => {
    try {
      if (busy) return;
      setBusy(true);
      setErr("");
      if (!wallet.publicKey || KR.locked || !poll) {
        throw new Error("Unlock keyring and connect wallet");
      }
      if (selected == null) throw new Error("Select a choice");

      setStage("Preparing keys & proof…");
      const eddsa = await getEddsa();
      const babyjub = await getBabyjub();
      const poseidon = await getPoseidon();
      const F = poseidon.F;

      const a = KR.accounts[KR.active] ?? KR.accounts[0];
      if (!a) throw new Error("No active ZK account");
      const accountId = idForAccount(a);
      const prv = a.prv;
      const pub: [bigint, bigint] = a.pub;

      const pollIdBig = BigInt(poll.poll_id);
      const existing = RK.getForPoll(accountId, pollIdBig);
      const oldSec: [bigint, bigint] = existing ? existing.pub : [0n, 0n];
      const newRec = await RK.generateForPoll();
      const newSec: [bigint, bigint] = newRec.pub;

      const C_PK: [bigint, bigint] = [
        BigInt("0x" + poll.coordinator_key[0]),
        BigInt("0x" + poll.coordinator_key[1]),
      ];

      const N_choices = BigInt(choices.length);
      const PollId = BigInt(poll.poll_id);
      const Choice = BigInt(selected + 1);

      setStage("Downloading census & building Merkle proof…");
      const ab: ArrayBuffer = await fetch(poll.census_url).then((r) =>
        r.arrayBuffer()
      );
      const censusBuf = new Uint8Array(ab);
      if (censusBuf.length % 32 !== 0) throw new Error("Bad census file");
      const myLeaf = poseidon.F.toObject(
        poseidon([pub[0], pub[1]]),
      ) as bigint;
      let found = -1;
      for (let off = 0, i = 0; off < censusBuf.length; off += 32, i++) {
        let x = 0n;
        for (let b = 0; b < 32; b++) x = (x << 8n) | BigInt(censusBuf[off + b]);
        if (x === myLeaf) {
          found = i;
          break;
        }
      }
      if (found < 0) throw new Error("Your key is not in the census");
      const leaves: bigint[] = [];
      for (let off = 0; off < censusBuf.length; off += 32) {
        let x = 0n;
        for (let b = 0; b < 32; b++) x = (x << 8n) | BigInt(censusBuf[off + b]);
        leaves.push(x);
      }
      const { path, pathPos } = await getMerkleProof(
        CENSUS_DEPTH,
        leaves,
        found,
      );

      const M_N = poseidon([PLATFORM_NAME, PollId]);
      const sigN = eddsa.signPoseidon(prv, M_N);
      const SignaturePoint: [bigint, bigint] = [
        F.toObject(sigN.R8[0]),
        F.toObject(sigN.R8[1]),
      ];
      const SignatureScalar = sigN.S;
      const sigHash = F.toObject(
        poseidon([
          SignatureScalar,
          SignaturePoint[0],
          SignaturePoint[1],
        ]),
      );

      const rnd = new Uint8Array(64);
      crypto.getRandomValues(rnd);
      let r = 0n;
      for (let i = 0; i < rnd.length; i++) r = (r << 8n) | BigInt(rnd[i]);
      r = (r % babyjub.subOrder) || 1n;
      const Rraw = babyjub.mulPointEscalar(babyjub.Base8, r);
      const C_Sraw = babyjub.mulPointEscalar([F.e(C_PK[0]), F.e(C_PK[1])], r);
      const C_S: [bigint, bigint] = [
        F.toObject(C_Sraw[0]),
        F.toObject(C_Sraw[1]),
      ];

      const R: [bigint, bigint] = [F.toObject(Rraw[0]), F.toObject(Rraw[1])];

      const RevotingKeyOld = oldSec;
      const RevotingKeyNew = newSec;
      let RevotingSignaturePoint: [bigint, bigint] = [0n, 0n];
      let RevotingSignatureScalar = 0n;
      if (oldSec[0] !== 0n || oldSec[1] !== 0n) {
        const prvRevoting = existing!.prv;
        const M2 = poseidon([
          PLATFORM_NAME,
          sigHash,
          Choice,
          RevotingKeyNew[0],
          RevotingKeyNew[1],
        ]);
        const sig2 = eddsa.signPoseidon(prvRevoting, M2);
        RevotingSignaturePoint = [
          F.toObject(sig2.R8[0]),
          F.toObject(sig2.R8[1]),
        ];
        RevotingSignatureScalar = sig2.S;
      }

      const nuCoordinator = F.toObject(poseidon([sigHash]));
      const C_P = [
        nuCoordinator,
        Choice,
        RevotingKeyOld[0],
        RevotingKeyOld[1],
        RevotingKeyNew[0],
        RevotingKeyNew[1],
      ];
      const Nonce = (() => {
        const u = new Uint32Array(2);
        crypto.getRandomValues(u);
        return (BigInt(u[0]) << 32n) | BigInt(u[1]);
      })();
      const C_CT = poseidonEncrypt(C_P, C_S, Nonce);

      const R_CT = [0n, 0n, 0n, 0n];
      const CoordinatorPK = C_PK;

      setStage("Generating proof… (this may take a bit)");
      const inputs = {
        CensusRoot: BigInt("0x" + poll.census_root),
        PollId,
        N_choices,
        RevotingKeyNew,
        RevotingKeyOld,
        RevotingSignaturePoint,
        RevotingSignatureScalar,
        Key: pub,
        SignaturePoint,
        SignatureScalar,
        Path: path,
        PathPos: pathPos,
        Choice,
        ephR: r,
        CoordinatorPK,
        RelayerPK: [0n, 0n],
        Nonce,
        C_CT,
        R_CT,
      };
      const { proof } = await groth16.fullProve(
        inputs,
        VOTE_WASM_URL,
        VOTE_ZKEY_URL,
      );
      const serializedProof = compressProof(proof);

      setStage("Sending transaction…");
      const platform = await fetchPlatformConfig(connection);
      const ix: InstructionWithCu = await vote({
        payer: wallet.publicKey,
        pollId: PollId,
        ciphertext: C_CT.map((c) => Array.from(toBytes32(c))),
        ephKey: {
          x: Array.from(toBytes32(R[0])),
          y: Array.from(toBytes32(R[1])),
        },
        nonce: Nonce,
        proof: {
          a: Array.from(serializedProof.a),
          b: Array.from(serializedProof.b),
          c: Array.from(serializedProof.c),
        },
        platformFeeDestination: platform!.feeDestination,
        pollFeeDestination: new PublicKey(poll.fee_destination),
      });

      const tx = new Transaction().add(
        cuLimitInstruction([ix]),
        ...[ix].map((x) => x.instruction),
      );
      tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
      tx.feePayer = wallet.publicKey;
      await wallet.sendTransaction(tx, connection, { maxRetries: 3 });

      await RK.setForPoll(accountId, pollIdBig, { ...newRec, title });
      setStage("Vote sent!");
    } catch (e: any) {
      console.error(e);
      setErr("Error: " + String(e?.message || e));
      setStage("");
    } finally {
      setBusy(false);
    }
  };

  if (!poll) {
    return (
      <Card title="Poll">
        {err
          ? <div className="text-sm text-red-600">{err}</div>
          : <div className="text-sm opacity-70">Loading…</div>}
      </Card>
    );
  }

  const now = Math.floor(Date.now() / 1000);
  const active = now >= poll.voting_start_time && now <= poll.voting_end_time;

  if (KR.locked) {
    return (
      <Card title="Vote">
        <p className="text-sm text-amber-600">
          Unlock your ZK keyring to view this poll and vote.
        </p>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-xl font-semibold truncate">{title}</h2>
          <div className="text-xs opacity-70">#{poll.poll_id}</div>
        </div>
        <span className="text-sm opacity-70">{clock.label}</span>
      </div>

      {clock.isActive && (
        <Card title="Your vote">
          {choices.length === 0
            ? (
              <div className="text-sm opacity-70">
                No choices found in description.
              </div>
            )
            : (
              <div className="space-y-2">
                {choices.map((c, i) => (
                  <label
                    key={i}
                    className="flex items-center gap-2 cursor-pointer"
                  >
                    <input
                      type="radio"
                      name="choice"
                      checked={selected === i}
                      onChange={() => setSelected(i)}
                    />
                    <span>{c}</span>
                  </label>
                ))}
              </div>
            )}
          <div className="mt-4 flex items-center gap-3">
            <button
              className={btn(!disabled)}
              disabled={disabled}
              onClick={onVoteClick}
            >
              {active ? "Cast vote" : "Voting closed"}
            </button>
            {stage && <span className="text-sm text-purple-600">{stage}</span>}
          </div>
          {err && <div className="mt-2 text-sm text-red-600">{err}</div>}
          {KR.locked && (
            <div className="mt-2 text-xs text-amber-600">
              Unlock your ZK keyring in “ZK Accounts”.
            </div>
          )}
          {!wallet.publicKey && (
            <div className="mt-2 text-xs text-amber-600">
              Connect your Solana wallet.
            </div>
          )}
        </Card>
      )}
      {!!poll?.tally && (
        <ResultsBars
          title="Results"
          choices={choices}
          tally={poll.tally}
        />
      )}
      {clock.isOver && !poll?.tally && (
        <p>Waiting for tallier to count the votes…</p>
      )}
    </div>
  );
};

type VoteRow = {
  id: string;
  eph_x: string;
  eph_y: string;
  nonce: string;
  ciphertext: string;
};

type VotesPage = {
  items: VoteRow[];
  next_after?: number | null;
  total: number;
};

function usePollClock(startSec: number, endSec: number) {
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const t = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(t);
  }, []);
  const isBefore = now < startSec;
  const isOver = now >= endSec;
  const secs = isBefore ? (startSec - now) : (isOver ? 0 : endSec - now);
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  const fmt = (n: number) => String(n).padStart(2, "0");
  const label = isBefore
    ? `Starts in ${fmt(h)}:${fmt(m)}:${fmt(s)}`
    : isOver
    ? `Ended`
    : `Ends in ${fmt(h)}:${fmt(m)}:${fmt(s)}`;
  return { label, isOver, isActive: !isBefore && !isOver };
}

const TallyPage: React.FC<{ pollId: bigint }> = ({ pollId }) => {
  const wallet = useWallet();
  const KR = useKeyringCtx();
  const connection = new Connection(RPC_URL, { commitment: "confirmed" });
  const [poll, setPoll] = useState<PollDetail | null>(null);
  const [desc, setDesc] = useState<{ title: string; choices: string[] } | null>(
    null,
  );
  const [store, setStore] = useState<TallyStore | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState<string>("");
  const [remaining, setRemaining] = useState<number | null>(null);
  const [clientTally, setClientTally] = useState<number[] | null>(null);

  const keypair = KR.accounts[KR.active];
  const accountId = `${keypair.pub[0].toString(16)}:${
    keypair.pub[1].toString(16)
  }`;

  const clock = usePollClock(
    poll?.voting_start_time ?? 0,
    poll?.voting_end_time ?? 0,
  );

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        setLoading(true);
        setErr("");
        const r = await fetch(`${INDEXER_URL}/polls/${pollId}`);
        if (!r.ok) throw new Error("Poll not found");
        const p = await r.json();
        if (!live) return;
        setPoll(p);
        if (p.title && p.choices) {
          setDesc({ title: p.title, choices: p.choices });
        } else if (p.description_url) {
          try {
            const dj = await fetch(p.description_url).then((x) => x.json());
            setDesc({
              title: dj.title ?? "Untitled poll",
              choices: dj.choices ?? [],
            });
          } catch {
            setDesc({ title: "Untitled poll", choices: [] });
          }
        } else {
          setDesc({ title: "Untitled poll", choices: [] });
        }
      } catch (e: any) {
        console.error(e);
        setErr("Error: " + String(e?.message || e));
      } finally {
        setLoading(false);
      }
    })();
    return () => {
      live = false;
    };
  }, [pollId]);

  useEffect(() => {
    if (!keypair) return;
    loadTallyStore(pollId, accountId).then(setStore);
  }, [pollId, accountId]);

  const refreshRemaining = useCallback(async () => {
    try {
      if (!store) {
        setRemaining(null);
        return;
      }
      const after = store.processedAfterId;
      const r = await fetch(
        `${INDEXER_URL}/polls/${pollId}/votes?limit=100&after=${after}`,
      );
      if (!r.ok) throw new Error("votes fetch");
      const j: VotesPage = await r.json();
      setRemaining(j.total - store.processedCount);
    } catch (e: any) {
      console.error(e);
      setRemaining(null);
    }
  }, [store, pollId]);

  useEffect(() => {
    refreshRemaining();
  }, [refreshRemaining]);

  const onCreateTally = useCallback(async () => {
    try {
      if (busy) return;
      setBusy(true);
      setStage("Creating tally account…");
      if (!wallet.publicKey) throw new Error("Connect Solana wallet");
      if (!keypair) throw new Error("No active ZK tallier key");
      if (!poll) throw new Error("Poll not loaded");

      const tally_before = Array(poll.choices.length).fill(0n);
      const saltU8 = new Uint8Array(8);
      crypto.getRandomValues(saltU8);
      let salt = 0n;
      for (const b of saltU8) salt = (salt << 8n) | BigInt(b);

      const poseidon = await getPoseidon();
      const F = poseidon.F;
      const tallyBeforeHash = F.toObject(
        poseidon([
          salt,
          ...tally_before,
          ...Array(MAX_CHOICES - tally_before.length).fill(0n),
        ]),
      );
      const initialTallyHashBytes = toBytes32(tallyBeforeHash);

      const ix = await createTally({
        initialTallyHash: Array.from(initialTallyHashBytes),
        payer: wallet.publicKey,
        pollId: BigInt(pollId),
      });
      const tx = new Transaction().add(
        cuLimitInstruction([ix]),
        ...[ix].map((x) => x.instruction),
      );
      tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
      tx.feePayer = wallet.publicKey;
      await wallet.sendTransaction(tx, connection, { maxRetries: 3 });

      const s: TallyStore = {
        pollId,
        accountId,
        processedAfterId: 0n,
        processedCount: 0,
        rootHex: "0x" + "00".repeat(32),
        runningMsgHashHex: "0x" + "00".repeat(32),
        tallyHashHex: toHex32(tallyBeforeHash),
        tallySaltHex: toHex32(salt),
        tallyCounts: tally_before.map((x) => x.toString(10)),
        leaves: {},
      };
      await saveTallyStore(s);
      setStore(s);
      await refreshRemaining();
      setStage("");
    } catch (e: any) {
      console.error(e);
      setErr("Error: " + String(e?.message || e));
      setStage("");
    } finally {
      setBusy(false);
    }
  }, [
    wallet.publicKey,
    poll,
    pollId,
    accountId,
    keypair,
    refreshRemaining,
    busy,
  ]);

  const onTallyNext = useCallback(async () => {
    try {
      if (busy) return;
      setBusy(true);
      setStage("Fetching votes to tally…");
      if (!wallet.publicKey) throw new Error("Connect Solana wallet");
      if (!keypair) throw new Error("No active ZK tallier key");
      if (!poll || !store) throw new Error("Poll/store not ready");
      const poseidon = await getPoseidon();
      const F = poseidon.F;

      const r = await fetch(
        `${INDEXER_URL}/polls/${pollId}/votes?limit=${MAX_BATCH}&after=${store.processedAfterId}`,
      );
      if (!r.ok) throw new Error("votes fetch failed");
      const page: VotesPage = await r.json();
      const batch = page.items;
      if (batch.length === 0) throw new Error("No new votes to tally");

      setStage("Generating proof… (this may take a bit)");
      const db = new InMemoryDB(new Uint8Array());
      const mt = new Merkletree(db, true, STATE_DEPTH);
      for (const [idxStr, { hash: leafHash }] of Object.entries(store.leaves)) {
        const idx = BigInt(idxStr);
        try {
          await mt.add(idx, leafHash);
        } catch (e) {
          if (e !== ErrEntryIndexAlreadyExists) throw e;
          await mt.update(idx, leafHash);
        }
      }
      const Root_before = (await mt.root()).bigInt();

      const C_SK = keypair.sk;
      let H = BigInt(store.runningMsgHashHex);
      const tallyCounts = store.tallyCounts.map((x) => BigInt(x));
      const leavesMap = { ...store.leaves };

      const EphKey: bigint[][] = [];
      const Nonce: bigint[] = [];
      const CT: bigint[][] = [];
      const Siblings: bigint[][] = [];
      const PrevChoice: bigint[] = [];
      const RevotingKeyOldActual: bigint[][] = [];
      const NoAux: bigint[] = [];
      const AuxKey: bigint[] = [];
      const AuxValue: bigint[] = [];
      const IsPrevEmpty: bigint[] = [];

      const LIMBS = 6;

      for (const v of batch) {
        const R: [bigint, bigint] = [
          BigInt("0x" + v.eph_x),
          BigInt("0x" + v.eph_y),
        ];
        const nonce = BigInt(v.nonce);
        const ctWords: bigint[] = [];
        const buf = Uint8Array.from(
          (v.ciphertext.match(/.{1,2}/g) ?? []).map((h) => parseInt(h, 16)),
        );
        if (buf.length % 32 !== 0) throw new Error("bad ciphertext len");
        for (let i = 0; i < buf.length; i += 32) {
          let x = 0n;
          for (let j = 0; j < 32; j++) x = (x << 8n) | BigInt(buf[i + j]);
          ctWords.push(x);
        }
        const shared = mulPointEscalar(R, C_SK);
        const plain = poseidonDecrypt(ctWords, shared, nonce, LIMBS);
        const [
          nu,
          choice,
          revotingKeyOldFromMsg0,
          revotingKeyOldFromMsg1,
          revotingKeyNew0,
          revotingKeyNew1,
        ] = plain;

        const idx = nu & ((1n << BigInt(STATE_DEPTH)) - 1n);
        const prevLeaf = leavesMap[idx.toString()];
        let prevChoice = 0n;
        let prevSec: [bigint, bigint] = [0n, 0n];
        if (prevLeaf) {
          prevChoice = prevLeaf.choice;
          prevSec = prevLeaf.revotingKey;
        }

        const voteIsValid = prevSec[0] == revotingKeyOldFromMsg0 &&
          prevSec[1] == revotingKeyOldFromMsg1;

        let proof: any;
        if (voteIsValid) {
          const leaf = F.toObject(
            poseidon([choice, revotingKeyNew0, revotingKeyNew1]),
          );
          try {
            proof = await mt.addAndGetCircomProof(idx, leaf);
            IsPrevEmpty.push(1n);
          } catch (e) {
            if (e !== ErrEntryIndexAlreadyExists) throw e;
            proof = await mt.update(idx, leaf);
            IsPrevEmpty.push(0n);
          }
          leavesMap[idx.toString()] = {
            choice,
            revotingKey: [revotingKeyNew0, revotingKeyNew1],
            hash: leaf,
          };
          if (prevChoice !== 0n) tallyCounts[Number(prevChoice) - 1] -= 1n;
          if (choice !== 0n) tallyCounts[Number(choice) - 1] += 1n;
        } else {
          proof = await mt.generateCircomVerifierProof(idx, ZERO_HASH);
          IsPrevEmpty.push(0n);
        }

        NoAux.push(BigInt(proof.isOld0));
        AuxKey.push(proof.oldKey.bigInt());
        AuxValue.push(proof.oldValue.bigInt());
        const siblings = proof.siblings.map((h: any) => h.bigInt());
        Siblings.push(siblings);
        PrevChoice.push(prevChoice);
        RevotingKeyOldActual.push(prevSec);
        EphKey.push(R);
        Nonce.push(nonce);
        CT.push(ctWords);

        const msgHash = F.toObject(poseidon([R[0], R[1], nonce, ...ctWords]));
        H = F.toObject(poseidon([H, msgHash]));
      }

      while (EphKey.length < MAX_BATCH) {
        EphKey.push(EphKey[EphKey.length - 1]);
        Nonce.push(Nonce[Nonce.length - 1]);
        CT.push(CT[CT.length - 1]);
        Siblings.push(Siblings[Siblings.length - 1]);
        PrevChoice.push(PrevChoice[PrevChoice.length - 1]);
        IsPrevEmpty.push(IsPrevEmpty[IsPrevEmpty.length - 1]);
        NoAux.push(NoAux[NoAux.length - 1]);
        AuxKey.push(AuxKey[AuxKey.length - 1]);
        AuxValue.push(AuxValue[AuxValue.length - 1]);
        RevotingKeyOldActual.push(
          RevotingKeyOldActual[RevotingKeyOldActual.length - 1],
        );
      }

      const Root_after = (await mt.root()).bigInt();
      let saltBefore = BigInt(store.tallySaltHex);
      const saltU8b = new Uint8Array(8);
      crypto.getRandomValues(saltU8b);
      let saltAfter = 0n;
      for (const b of saltU8b) saltAfter = (saltAfter << 8n) | BigInt(b);

      const Tally_before = Array(MAX_CHOICES).fill(0n);
      for (let i = 0; i < MAX_CHOICES; i++) {
        Tally_before[i] = BigInt(store.tallyCounts[i] ?? "0");
      }
      const Tally_after = Tally_before.slice();
      for (let i = 0; i < MAX_CHOICES; i++) {
        Tally_after[i] = tallyCounts[i] ?? 0n;
      }

      const TallyHash_before = BigInt(store.tallyHashHex);
      const H_before = BigInt(store.runningMsgHashHex);

      const tallyAfterHash = F.toObject(poseidon([saltAfter, ...Tally_after]));

      const inputs = {
        Root_before,
        H_before,
        TallyHash_before,
        TallySalt_before: saltBefore,
        TallySalt_after: saltAfter,
        Tally_before,
        BatchLen: BigInt(batch.length),
        SK: C_SK,
        EphKey,
        Nonce,
        CT,
        Siblings,
        PrevChoice,
        RevotingKeyOldActual,
        NoAux,
        AuxKey,
        AuxValue,
        IsPrevEmpty,
      };

      const { proof, publicSignals } = await groth16.fullProve(
        inputs,
        TALLY_WASM_URL,
        TALLY_ZKEY_URL,
      );
      const Root_after_pub = BigInt(publicSignals[0]);
      const H_after_pub = BigInt(publicSignals[1]);
      const TallyHash_after_pub = BigInt(publicSignals[2]);
      if (Root_after_pub !== Root_after) throw new Error("Root_after mismatch");
      if (TallyHash_after_pub !== tallyAfterHash) {
        throw new Error("TallyHash_after mismatch");
      }

      setStage("Sending transaction…");
      const serialized = compressProof(proof);
      const ix = await tallyBatch({
        pollId: BigInt(pollId),
        proof: {
          a: Array.from(serialized.a),
          b: Array.from(serialized.b),
          c: Array.from(serialized.c),
        },
        owner: wallet.publicKey,
        rootAfter: Array.from(toBytes32(Root_after)),
        runningMsgHashAfter: Array.from(toBytes32(H_after_pub)),
        tallyHashAfter: Array.from(toBytes32(TallyHash_after_pub)),
      });
      const tx = new Transaction().add(
        cuLimitInstruction([ix]),
        ...[ix].map((x) => x.instruction),
      );
      tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
      tx.feePayer = wallet.publicKey;
      await wallet.sendTransaction(tx, connection, { maxRetries: 3 });

      const lastId = BigInt(batch[batch.length - 1].id);
      const newStore: TallyStore = {
        ...store,
        processedAfterId: lastId,
        processedCount: store.processedCount + batch.length,
        rootHex: toHex32(Root_after),
        runningMsgHashHex: toHex32(H_after_pub),
        tallyHashHex: toHex32(TallyHash_after_pub),
        tallySaltHex: toHex32(saltAfter),
        tallyCounts: tallyCounts.map((x) => x.toString(10)),
        leaves: leavesMap,
      };
      await saveTallyStore(newStore);
      setStore(newStore);
      await refreshRemaining();
      setStage("Tally batch submitted");
    } catch (e: any) {
      console.error(e);
      setErr("Error: " + String(e?.message || e));
      setStage("");
    } finally {
      setBusy(false);
    }
  }, [wallet.publicKey, poll, store, keypair, pollId, refreshRemaining, busy]);

  const onFinishTally = useCallback(async () => {
    try {
      if (busy) return;
      setBusy(true);
      setStage("Sending transaction…");
      if (!wallet.publicKey) throw new Error("Connect Solana wallet");
      if (!poll || !store) throw new Error("Poll/store not ready");
      const finalCounts = store.tallyCounts.map((x) => BigInt(x));
      const finalSalt = BigInt(store.tallySaltHex);
      const ix = await finishTally({
        pollId: BigInt(pollId),
        payer: wallet.publicKey,
        tally: finalCounts,
        tallySalt: finalSalt,
      });
      const tx = new Transaction().add(ix.instruction);
      tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
      tx.feePayer = wallet.publicKey;
      await wallet.sendTransaction(tx, connection, { maxRetries: 3 });
      setStage("Tally finished");
      setClientTally(store.tallyCounts.map((x) => Number(x)));
    } catch (e: any) {
      console.error(e);
      setErr("Error: " + String(e?.message || e));
      setStage("");
    } finally {
      setBusy(false);
    }
  }, [wallet.publicKey, poll, store, pollId, busy]);

  const onResetTally = useCallback(async () => {
    if (!store) return;
    const ok = confirm(
      "Reset tally progress? This will clear your local state.",
    );
    if (!ok) return;
    resetTallyStore(pollId, accountId);
    setStore(null);
    await refreshRemaining();
  }, [store, refreshRemaining]);

  if (KR.locked) {
    return (
      <Card title="Tally">
        <p className="text-sm text-amber-600">
          Unlock your ZK keyring to view this poll and tally.
        </p>
      </Card>
    );
  }

  if (loading) return <div className="p-4">Loading…</div>;
  if (!poll || !desc) return <div className="p-4">No poll.</div>;

  const effectiveTally = clientTally ?? poll?.tally ?? null;
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold">{desc.title}</h2>
          <div className="text-xs opacity-70">#{pollId}</div>
        </div>
        <span className="text-sm opacity-70">{clock.label}</span>
      </div>

      {Array.isArray(effectiveTally) && (
        <ResultsBars
          title="Results"
          choices={poll.choices}
          tally={effectiveTally!}
        />
      )}
      {!Array.isArray(effectiveTally) && (
        <Card className="mt-4">
          {store && (
            <div className="mt-4">
              {(() => {
                const processed = store.processedCount;
                const rem = remaining ?? 0;
                const total = Math.max(1, processed + rem);
                const pct = Math.max(
                  0,
                  Math.min(100, Math.round((processed / total) * 100)),
                );
                return (
                  <div className="flex items-center gap-2">
                    <div className="relative h-2 w-full rounded bg-gray-200 dark:bg-zinc-800 overflow-hidden">
                      <div
                        className="h-full bg-emerald-600 dark:bg-emerald-500 transition-[width] duration-300"
                        style={{ width: `${pct}%` }}
                        aria-valuemin={0}
                        aria-valuemax={100}
                        aria-valuenow={pct}
                        role="progressbar"
                      />
                    </div>
                    <button
                      onClick={refreshRemaining}
                      disabled={busy}
                      title="Refresh remaining"
                      className="p-1 rounded hover:bg-gray-100 dark:hover:bg-zinc-800 disabled:opacity-60"
                      aria-label="Refresh remaining"
                    >
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        viewBox="0 0 32 32"
                        width="32px"
                        height="32px"
                      >
                        <path
                          fill="#AB7C94"
                          d="M 16 4 C 10.886719 4 6.617188 7.160156 4.875 11.625 L 6.71875 12.375 C 8.175781 8.640625 11.710938 6 16 6 C 19.242188 6 22.132813 7.589844 23.9375 10 L 20 10 L 20 12 L 27 12 L 27 5 L 25 5 L 25 8.09375 C 22.808594 5.582031 19.570313 4 16 4 Z M 25.28125 19.625 C 23.824219 23.359375 20.289063 26 16 26 C 12.722656 26 9.84375 24.386719 8.03125 22 L 12 22 L 12 20 L 5 20 L 5 27 L 7 27 L 7 23.90625 C 9.1875 26.386719 12.394531 28 16 28 C 21.113281 28 25.382813 24.839844 27.125 20.375 Z"
                        />
                      </svg>
                    </button>
                    <div className="text-xs tabular-nums w-20 text-right">
                      {processed}/{total}
                    </div>
                  </div>
                );
              })()}
            </div>
          )}
          {!store && (
            <p className="text-sm">
              To count votes, first initialize the tally.
            </p>
          )}
          <div className="mt-4 flex items-center gap-2">
            {!store && (
              <button
                className={btn(!busy && !!wallet.publicKey)}
                disabled={busy || !wallet.publicKey}
                onClick={onCreateTally}
              >
                Start tally
              </button>
            )}
            {store && (
              <>
                {remaining !== 0 && remaining !== null && (
                  <button
                    className={btn(!busy && !!wallet.publicKey)}
                    disabled={busy || !wallet.publicKey}
                    onClick={onTallyNext}
                  >
                    Tally next batch
                  </button>
                )}
                {Date.now() / 1000 >= poll.voting_end_time && remaining === 0 &&
                  (
                    <button
                      className={btn(!busy && !!wallet.publicKey)}
                      disabled={busy || !wallet.publicKey}
                      onClick={onFinishTally}
                    >
                      Finish Tally
                    </button>
                  )}
              </>
            )}
            <span className="text-sm text-purple-600">{stage}</span>
            {err && (
              <span className="text-sm text-red-500 whitespace-pre-wrap">
                {err}
              </span>
            )}
            {/* We don't want to hide it when poll is over, server may lag... */}
            {store && (
              <>
                <button
                  className="ml-auto px-3 py-2 text-xs underline opacity-70"
                  disabled={busy}
                  onClick={onResetTally}
                >
                  Reset tally
                </button>
              </>
            )}
          </div>
        </Card>
      )}
    </div>
  );
};

const VoteRoute: React.FC = () => {
  const { id } = useParams();
  return <VotePage pollId={BigInt(id!)} />;
};

const TallyRoute: React.FC = () => {
  const { id } = useParams();
  return <TallyPage pollId={BigInt(id!)} />;
};

const navItemClass = ({ isActive }: { isActive: boolean }) =>
  [
    "block rounded-lg px-3 py-2 text-sm font-medium transition-colors",
    "hover:bg-gray-200 hover:text-black dark:hover:bg-zinc-800 dark:hover:text-white",
    isActive
      ? "bg-gray-200 text-black dark:bg-zinc-800 dark:text-white"
      : "text-gray-700 dark:text-zinc-300",
  ].join(" ");

const Layout: React.FC<{ setShowAccounts: (showAccounts: boolean) => void }> = (
  { setShowAccounts },
) => {
  const [open, setOpen] = useState(false);
  const headerRef = useRef<HTMLElement | null>(null);
  const [headerH, setHeaderH] = useState<number>(72);

  useEffect(() => {
    if (!headerRef.current) return;
    setHeaderH(headerRef.current.getBoundingClientRect().height);
    const ro = new ResizeObserver((entries) => {
      const h = entries[0]?.contentRect?.height;
      if (h) setHeaderH(h);
    });
    ro.observe(headerRef.current);
    return () => ro.disconnect();
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 dark:from-zinc-950 dark:to-zinc-900 text-gray-900 dark:text-zinc-100">
      <header
        ref={headerRef}
        className="sticky top-0 z-40 border-b border-gray-200/60 dark:border-zinc-800/60 bg-white/70 dark:bg-zinc-950/70 backdrop-blur"
      >
        <div className="mx-auto max-w-7xl px-4 py-3 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <button
              className="md:hidden rounded-lg border px-2 py-1 text-sm"
              onClick={() => setOpen((v) => !v)}
              aria-label="Toggle navigation"
            >
              ☰
            </button>
            <h1 className="text-xl font-bold leading-none">AnonVote</h1>

            {CLUSTER === "devnet" && (
              <span
                className="text-xs px-2 py-1 rounded-full bg-indigo-100 text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300"
                title="On devnet, polls are free to create, as SOL can be retrieved via faucets. However, security and correctness are not guaranteed."
              >
                DEVNET
              </span>
            )}
            {OTHER_ENV_URL && (
              <a
                href={OTHER_ENV_URL}
                className="text-xs underline opacity-80 hover:opacity-100"
                target="_self"
              >
                {CLUSTER === "devnet" ? "Go to mainnet" : "Go to devnet"}
              </a>
            )}
          </div>

          <div className="flex items-center gap-2">
            <ThemeToggle />
            <ZkAccountsButton onClick={() => setShowAccounts(true)} />
            <WalletMultiButton />
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-4 flex gap-4">
        {/* Sidebar (desktop) */}
        <aside
          className="hidden md:flex w-60 shrink-0 pt-4 sticky flex-col justify-between"
          style={{ top: headerH, height: `calc(100vh - ${headerH + 1}px)` }}
        >
          <nav className="space-y-1">
            <NavLink to="/create" className={navItemClass}>
              Create Poll
            </NavLink>
            <NavLink to="/my/voter" className={navItemClass}>
              Vote
            </NavLink>
            <NavLink to="/my/tallier" className={navItemClass}>
              Tally
            </NavLink>
          </nav>

          {/* Socials footer */}
          <div className="mt-auto pt-4 border-t border-gray-200 dark:border-zinc-800">
            <div className="flex items-center gap-2">
              <a
                href={GITHUB_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center justify-center rounded-lg p-2 hover:bg-gray-200 dark:hover:bg-zinc-800"
                aria-label="GitHub"
                title="GitHub"
              >
                <img
                  src="/icons/github-mark.svg"
                  alt="GitHub"
                  className="h-5 w-5 block dark:hidden"
                />
                <img
                  src="/icons/github-mark-white.svg"
                  alt="GitHub"
                  className="h-5 w-5 hidden dark:block"
                />
              </a>
            </div>
          </div>
        </aside>

        {/* Drawer (mobile) */}
        {open && (
          <div
            className="md:hidden fixed inset-x-0 bottom-0 z-30"
            style={{ top: headerH }}
            onClick={() => setOpen(false)}
          >
            <div
              className="absolute inset-0 bg-black/30"
              aria-hidden="true"
            />
            <div
              className="absolute left-0 top-0 h-full w-64 bg-white dark:bg-zinc-950 border-r border-gray-200 dark:border-zinc-800 p-3"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex h-full flex-col">
                <nav className="space-y-1">
                  <NavLink
                    to="/create"
                    className={navItemClass}
                    onClick={() => setOpen(false)}
                  >
                    Create Poll
                  </NavLink>
                  <NavLink
                    to="/my/voter"
                    className={navItemClass}
                    onClick={() => setOpen(false)}
                  >
                    Vote
                  </NavLink>
                  <NavLink
                    to="/my/tallier"
                    className={navItemClass}
                    onClick={() => setOpen(false)}
                  >
                    Tally
                  </NavLink>
                </nav>

                {/* Socials footer (mobile) */}
                <div className="mt-auto pt-3 border-t border-gray-200 dark:border-zinc-800">
                  <div className="flex items-center gap-2">
                    <a
                      href={GITHUB_URL}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center justify-center rounded-lg p-2 hover:bg-gray-200 dark:hover:bg-zinc-800"
                      aria-label="GitHub"
                      title="GitHub"
                    >
                      <img
                        src="/icons/github-mark.svg"
                        alt="GitHub"
                        className="h-5 w-5 block dark:hidden"
                      />
                      <img
                        src="/icons/github-mark-white.svg"
                        alt="GitHub"
                        className="h-5 w-5 hidden dark:block"
                      />
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        <main className="flex-1 min-w-0 py-4">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

const Inner: React.FC = () => {
  const wallets = useMemo(
    () => [new SolflareWalletAdapter(), new LedgerWalletAdapter()],
    [],
  );
  const [showAccounts, setShowAccounts] = useState(false);
  return (
    <ConnectionProvider endpoint={RPC_URL}>
      <WalletProvider wallets={wallets} autoConnect>
        <WalletModalProvider>
          <KeyringProvider>
            <RevoKeysProvider>
              <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 text-gray-900 dark:from-neutral-950 dark:to-neutral-900 dark:text-neutral-100">
                <Routes>
                  <Route element={<Layout setShowAccounts={setShowAccounts} />}>
                    <Route
                      path="/"
                      element={<Navigate to="/create" replace />}
                    />
                    <Route path="/create" element={<PollCreator />} />
                    <Route path="/my/voter" element={<MyVoterPolls />} />
                    <Route
                      path="/my/tallier"
                      element={<MyCoordinatorPolls />}
                    />
                    <Route path="/tally/:id" element={<TallyRoute />} />
                    <Route path="/poll/:id" element={<VoteRoute />} />
                  </Route>
                </Routes>

                <AccountDrawer
                  open={showAccounts}
                  onClose={() => setShowAccounts(false)}
                />
              </div>
            </RevoKeysProvider>
          </KeyringProvider>
        </WalletModalProvider>
      </WalletProvider>
    </ConnectionProvider>
  );
};

export default function App() {
  return (
    <BrowserRouter>
      <Inner />
    </BrowserRouter>
  );
}
