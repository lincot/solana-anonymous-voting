import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { useFieldArray, useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { clusterApiUrl, Connection, Transaction } from "@solana/web3.js";
import { WalletAdapterNetwork } from "@solana/wallet-adapter-base";
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
import { get, set } from "idb-keyval";
import {
  buildBabyjub,
  buildEddsa,
  buildPoseidon,
  type Poseidon,
} from "circomlibjs";
import {
  createPoll,
  cuLimitInstruction,
  type InstructionWithCu,
  setProvider as setAnonProvider,
} from "@lincot/anon-vote-sdk";
import "@solana/wallet-adapter-react-ui/styles.css";
import type BaseWebIrys from "@irys/web-upload/esm/base";
import { getMerkleRoot } from "../../helpers/merkletree.ts";
import "./index.css";

const MAX_CHOICES = 8;
const CENSUS_DEPTH = 40;

const INDEXER_URL = import.meta.env.VITE_INDEXER_URL;

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
      "rounded-2xl shadow p-4 border bg-white/80 border-gray-200",
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
  sk: string;
  pkX: string;
  pkY: string;
  createdAt: number;
};

type EncryptedKeyringBlob = {
  v: 1;
  saltB64: string;
  ivB64: string;
  ctB64: string;
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
  const pt = new TextEncoder().encode(JSON.stringify(obj));
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
  return JSON.parse(new TextDecoder().decode(pt));
}

const hexToBytes32 = (hex: string): Uint8Array => {
  const s = hex.replace(/^0x/, "");
  if (s.length !== 64) throw new Error("Expected 32-byte hex");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
};

const bytesToHex = (b: Uint8Array) =>
  "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");

const bigintTo32be = (n: bigint) => {
  const out = new Uint8Array(32);
  let x = n;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
};
const hex32 = (n: bigint) => bytesToHex(bigintTo32be(n));

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

async function genBabyJubKeypair(name: string): Promise<BabyJubKeypair> {
  const eddsa = await buildEddsa();
  const babyjub = await buildBabyjub();
  const rnd = new Uint8Array(250);
  crypto.getRandomValues(rnd);
  const pk = eddsa.prv2pub(rnd);
  return {
    name,
    sk: hex32(babyjub.F.toObject(rnd)).slice(2),
    pkX: hex32(babyjub.F.toObject(pk[0])).slice(2),
    pkY: hex32(babyjub.F.toObject(pk[1])).slice(2),
    createdAt: Date.now(),
  };
}

const KEYRING_DB_KEY = "anonvote:keyring:v1";

function useKeyring() {
  const [locked, setLocked] = useState(true);
  const [pass, setPass] = useState("");
  const [accounts, setAccounts] = useState<BabyJubKeypair[]>([]);
  const [active, setActive] = useState<number>(0);
  const [hasKeyring, setHasKeyring] = useState<boolean | null>(null);

  useEffect(() => {
    (async () => {
      const blob = (await get(KEYRING_DB_KEY)) as
        | EncryptedKeyringBlob
        | undefined;
      setHasKeyring(!!blob);
    })();
  }, []);

  const unlock = useCallback(async () => {
    const blob = (await get(KEYRING_DB_KEY)) as
      | EncryptedKeyringBlob
      | undefined;
    if (!blob) {
      const firstBlob = await encryptToBlob(pass, [] as BabyJubKeypair[]);
      await set(KEYRING_DB_KEY, firstBlob);
      setAccounts([]);
      setLocked(false);
      setHasKeyring(true);
      return true;
    }
    try {
      const accs = await decryptFromBlob<BabyJubKeypair[]>(pass, blob);
      setAccounts(accs);
      setLocked(false);
      return true;
    } catch {
      alert("Wrong passphrase or corrupted keyring");
      return false;
    }
  }, [pass]);

  const persist = useCallback(async (next: BabyJubKeypair[]) => {
    const blob = await encryptToBlob(pass, next);
    await set(KEYRING_DB_KEY, blob);
    setAccounts(next);
  }, [pass]);

  const addNew = useCallback(async (name: string) => {
    const k = await genBabyJubKeypair(name);
    await persist([...accounts, k]);
  }, [accounts, persist]);

  // TODO check if already exists, imported successfully mark
  const importSk = useCallback(async (name: string, skHex: string) => {
    const eddsa = await buildEddsa();
    const babyjub = await buildBabyjub();
    const F = babyjub.F;
    const sk = BigInt("0x" + skHex.replace(/^0x/, ""));
    const pk = eddsa.prv2pub(F.e(sk));
    const pkX = hex32(babyjub.F.toObject(pk[0])).slice(2);
    const pkY = hex32(babyjub.F.toObject(pk[1])).slice(2);
    const k: BabyJubKeypair = {
      name,
      sk: skHex.replace(/^0x/, ""),
      pkX,
      pkY,
      createdAt: Date.now(),
    };
    await persist([...accounts, k]);
  }, [accounts, persist]);

  const removeAt = useCallback(async (idx: number) => {
    const next = accounts.slice();
    next.splice(idx, 1);
    await persist(next);
    if (active >= next.length) setActive(Math.max(0, next.length - 1));
  }, [accounts, active, persist]);

  const exportJson = useCallback(() => {
    const blob = new Blob([JSON.stringify(accounts, null, 2)], {
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
    importSk,
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

const strip0x = (s: string) => s.replace(/^0x/, "").toLowerCase();

async function keyToLeafHex(pkX: string, pkY: string): Promise<string> {
  const P = await getPoseidon();
  const F = P.F;
  const x = BigInt("0x" + strip0x(pkX));
  const y = BigInt("0x" + strip0x(pkY));
  const leaf = F.toObject(P([x, y]));
  return Array.from(bigintTo32be(leaf)).map((b) =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

const HEX32 = /^0x?[0-9a-fA-F]{64}$/;

const schema = z.object({
  pollId: z.string().regex(/^\d+$/, "Digits only"),
  title: z.string().min(1, "Title is required").max(200, "Keep it short"),
  choices: z.array(z.object({ value: z.string().min(1, "Required") }))
    .min(1, "At least one choice").max(
      MAX_CHOICES,
      `Max ${MAX_CHOICES} choices`,
    ),
  coordX: z.string().regex(HEX32, "32-byte hex"),
  coordY: z.string().regex(HEX32, "32-byte hex"),
  start: z.string().min(1, "Start required"),
  end: z.string().min(1, "End required"),
  feeLamports: z.string().regex(/^\d+$/, "Integer lamports"),
  censusBytes: z.instanceof(Uint8Array, { message: "Upload census .bin" }),
  censusCount: z.number().int().positive("Census empty"),
  censusRootHex: z.string().regex(/^0x[0-9a-fA-F]{64}$/, "Invalid root"),
}).refine(
  (d) =>
    !isNaN(Date.parse(d.start)) && !isNaN(Date.parse(d.end)) &&
    Date.parse(d.end) > Date.parse(d.start),
  { message: "End must be after start", path: ["end"] },
);

type FormValues = z.infer<typeof schema>;
type Stage =
  | "idle"
  | "uploading data to Irys"
  | "creating poll"
  | "done"
  | "error";

const PollCreator: React.FC<{}> = () => {
  const wallet = useWallet();
  const KR = useKeyringCtx();
  const [coordMode, setCoordMode] = useState<"keyring" | "manual">("keyring");
  const [coordIndex, setCoordIndex] = useState<number>(0);
  const [cluster, setCluster] = useState<WalletAdapterNetwork>(
    WalletAdapterNetwork.Devnet,
  );
  const [rpc, setRpc] = useState<string>(clusterApiUrl("devnet"));
  const [connection, setConnection] = useState<Connection | null>(null);

  useEffect(() => {
    const conn = new Connection(rpc, { commitment: "confirmed" });
    setConnection(conn);
  }, [rpc]);

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
      coordX: "",
      coordY: "",
      start: new Date(Date.now() + 60_000).toISOString().slice(0, 16),
      end: new Date(Date.now() + 3_600_000).toISOString().slice(0, 16),
      feeLamports: "0",
      censusBytes: undefined,
      censusCount: 0,
      censusRootHex: "0x" + "0".repeat(64),
    },
  });

  useEffect(() => {
    if (coordMode !== "keyring") return;
    const accs = KR.accounts;
    const idx = accs[coordIndex] ? coordIndex : KR.active ?? 0;
    const a = accs[idx];
    if (!a) return;
    setValue("coordX", "0x" + a.pkX, { shouldValidate: true });
    setValue("coordY", "0x" + a.pkY, { shouldValidate: true });
  }, [coordMode, coordIndex, KR.accounts, KR.active, setValue]);

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
        { devnet: cluster === WalletAdapterNetwork.Devnet, rpc },
      );
      console.log("desc url", descUrl, "\ncensus url", censusUrl);

      setStage("creating poll");

      const id = BigInt(data.pollId);
      const start = Math.floor(new Date(data.start).getTime() / 1000);
      const end = Math.floor(new Date(data.end).getTime() / 1000);
      const fee = BigInt(data.feeLamports);

      const ix: InstructionWithCu = await createPoll({
        payer: wallet.publicKey!,
        id,
        censusRoot: Array.from(hexToBytes32(data.censusRootHex)),
        coordinatorKey: {
          x: Array.from(hexToBytes32(data.coordX)),
          y: Array.from(hexToBytes32(data.coordY)),
        },
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

      await wallet.sendTransaction(tx, connection!, {
        maxRetries: 3,
        skipPreflight: true,
      });

      setStage("done");
    } catch (e: any) {
      console.error(e);
      setErrMsg(String(e?.message || e));
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
  };

  const inputCN = "w-full rounded border px-3 py-2 " +
    "border-gray-300 focus:outline-none focus:ring-2 focus:ring-black/20 " +
    "dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100 placeholder-neutral-400";

  const btnPrimary = (enabled: boolean) =>
    `px-4 py-2 rounded-lg text-white ${
      enabled
        ? "bg-black hover:bg-neutral-800"
        : "bg-gray-400 cursor-not-allowed"
    }`;

  return (
    <form
      onSubmit={handleSubmit(onSubmit)}
      className="max-w-3xl mx-auto p-4 rounded-2xl border bg-white border-gray-200 dark:bg-neutral-900 dark:border-neutral-800"
    >
      <h2 className="text-xl font-semibold mb-3">Create Poll</h2>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="space-y-3">
          <label className="block text-sm font-medium">Cluster</label>
          <select
            value={cluster}
            onChange={(e) => {
              const val = e.target.value as WalletAdapterNetwork;
              setCluster(val);
              setRpc(
                val === WalletAdapterNetwork.Devnet
                  ? clusterApiUrl("devnet")
                  : clusterApiUrl("mainnet-beta"),
              );
            }}
            className={inputCN}
          >
            <option value={WalletAdapterNetwork.Devnet}>devnet</option>
            <option value={WalletAdapterNetwork.Mainnet}>mainnet-beta</option>
          </select>

          <label className="block text-sm font-medium">RPC URL</label>
          <input
            className={inputCN}
            value={rpc}
            onChange={(e) => setRpc(e.target.value)}
          />

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
            <label className="block text-sm font-medium">Coordinator key</label>
            <div className="flex gap-2">
              <select
                className={inputCN}
                value={coordMode}
                onChange={(e) =>
                  setCoordMode(e.target.value as "keyring" | "manual")}
              >
                <option value="keyring">Use keyring key</option>
                <option value="manual">Enter manually</option>
              </select>
              {coordMode === "keyring" && (
                <select
                  className={inputCN}
                  value={coordIndex}
                  onChange={(e) => setCoordIndex(parseInt(e.target.value))}
                  disabled={KR.locked || KR.accounts.length === 0}
                  title={KR.locked ? "Unlock keyring in Accounts" : undefined}
                >
                  {KR.accounts.map((a, i) => (
                    <option key={i} value={i}>
                      {`${a.name} …${a.pkX.slice(-6)}`}
                    </option>
                  ))}
                </select>
              )}
            </div>
            <input
              placeholder="0x… (X)"
              className={cn(inputCN, "font-mono")}
              {...register("coordX")}
              readOnly={coordMode === "keyring"}
            />
            {errors.coordX && (
              <p className="text-red-500 text-xs">{errors.coordX.message}</p>
            )}
            <input
              placeholder="0x… (Y)"
              className={cn(inputCN, "font-mono")}
              {...register("coordY")}
              readOnly={coordMode === "keyring"}
            />
            {errors.coordY && (
              <p className="text-red-500 text-xs">{errors.coordY.message}</p>
            )}
            {coordMode === "keyring" && KR.locked && (
              <p className="text-xs text-amber-600">
                Unlock the keyring in the Accounts panel to use your keys.
              </p>
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
          className={btnPrimary(
            isValid && !!wallet.publicKey && stage === "idle" && !isSubmitting,
          )}
          disabled={isSubmitting || !wallet.publicKey || stage !== "idle"}
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
    label = `${a.name} · …${a.pkX.slice(-6)}`;
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

const KeyringPanel: React.FC = () => {
  const KR = useKeyringCtx();
  const [newName, setNewName] = useState("");
  const [importName, setImportName] = useState("");
  const [importSk, setImportSk] = useState("");
  const [confirmPass, setConfirmPass] = useState("");
  const creating = KR.hasKeyring === false;

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
            Private scalar (hex)
          </label>
          <input
            value={importSk}
            onChange={(e) => setImportSk(e.target.value)}
            className="w-full rounded border px-3 py-2 font-mono border-gray-300 dark:bg-neutral-800 dark:border-neutral-700 dark:text-neutral-100"
          />
        </div>
        <button
          onClick={() =>
            KR.importSk(importName || `import-${Date.now()}`, importSk)}
          className="rounded-lg px-4 py-2 border dark:border-neutral-700"
        >
          Import
        </button>
      </div>

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
                pkX: 0x{a.pkX}
              </div>
              <div className="text-xs font-mono break-all">pkY: 0x{a.pkY}</div>
              <details className="mt-1">
                <summary className="text-xs text-neutral-600 dark:text-neutral-400 cursor-pointer select-none">
                  show secret
                </summary>
                <div className="text-xs font-mono break-all">sk: 0x{a.sk}</div>
              </details>
            </div>
          ))}
        </div>
      </div>
    </Card>
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
          <KeyringPanel />
        </div>
      </div>
    </div>
  );
};

type PollItem = {
  poll_id: number;
  voting_start_time: number;
  voting_end_time: number;
  title: string;
  choices: string[];
};

type PollPage = { items: PollItem[]; next_after?: number | null };

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

const PollRow: React.FC<{ p: PollItem }> = ({ p }) => {
  const now = Date.now();
  const meta = pollStatusMeta(now, p.voting_start_time, p.voting_end_time);
  const go = () => {
    location.hash = `#/poll/${p.poll_id}`;
  };
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={go}
      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && go()}
      className="rounded-xl border p-3 border-gray-200 dark:border-neutral-800 cursor-pointer
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
    </div>
  );
};

const MyVoterPolls: React.FC = () => {
  const KR = useKeyringCtx();
  const [leafHex, setLeafHex] = useState<string>("");
  const [page, setPage] = useState<PollPage | null>(null);
  const [after, setAfter] = useState<number>(0);
  const [stack, setStack] = useState<number[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    (async () => {
      const acc = KR.accounts[KR.active] ?? KR.accounts[0];
      if (!acc) return;
      const leaf = await keyToLeafHex("0x" + acc.pkX, "0x" + acc.pkY);
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
        url.searchParams.set("limit", "20");
        const r = await fetch(url.toString());
        const j: PollPage = await r.json();
        setPage(j);
      } finally {
        setLoading(false);
      }
    })();
  }, [leafHex, after]);

  const next = () => {
    if (!page || page.next_after == null) return;
    setStack((s) => [...s, after]);
    setAfter(page.next_after!);
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
                  (!page || page.next_after == null || loading)
                    ? "opacity-50 cursor-not-allowed"
                    : "hover:bg-neutral-100 dark:hover:bg-neutral-800"
                }`}
                onClick={next}
                disabled={loading || !page || page.next_after == null}
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

  useEffect(() => {
    const acc = KR.accounts[KR.active] ?? KR.accounts[0];
    if (!acc) return;
    setXyHex((acc.pkX + acc.pkY).toLowerCase());
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
        const j: PollPage = await r.json();
        setPage(j);
      } finally {
        setLoading(false);
      }
    })();
  }, [xyHex, after]);

  const next = () => {
    if (!page || page.next_after == null) return;
    setStack((s) => [...s, after]);
    setAfter(page.next_after!);
  };
  const prev = () => {
    if (stack.length === 0) return;
    const s = stack.slice();
    const a = s.pop()!;
    setStack(s);
    setAfter(a);
  };

  return (
    <Card title="Coordinate">
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
                  (!page || page.next_after == null || loading)
                    ? "opacity-50 cursor-not-allowed"
                    : "hover:bg-neutral-100 dark:hover:bg-neutral-800"
                }`}
                onClick={next}
                disabled={loading || !page || page.next_after == null}
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

const Inner: React.FC = () => {
  const wallets = useMemo(
    () => [new SolflareWalletAdapter(), new LedgerWalletAdapter()],
    [],
  );
  const [showAccounts, setShowAccounts] = useState(false);
  const [page, setPage] = useState<"create" | "myVoter" | "myCoord">("create");
  return (
    <ConnectionProvider endpoint={clusterApiUrl("devnet")}>
      <WalletProvider wallets={wallets} autoConnect>
        <WalletModalProvider>
          <KeyringProvider>
            <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 text-gray-900 dark:from-neutral-950 dark:to-neutral-900 dark:text-neutral-100">
              <div className="max-w-5xl mx-auto p-4 space-y-4">
                <header className="flex items-center justify-between">
                  <h1 className="text-2xl font-bold">AnonVote</h1>
                  <div className="flex items-center gap-2">
                    <nav className="hidden sm:flex items-center gap-1 mr-2">
                      <button
                        className={cn(
                          "px-3 py-1 rounded-lg border text-sm dark:border-neutral-700",
                          page === "create"
                            ? "bg-neutral-900 text-white dark:bg-white dark:text-neutral-900"
                            : "hover:bg-neutral-100 dark:hover:bg-neutral-800",
                        )}
                        onClick={() => setPage("create")}
                      >
                        Create
                      </button>
                      <button
                        className={cn(
                          "px-3 py-1 rounded-lg border text-sm dark:border-neutral-700",
                          page === "myVoter"
                            ? "bg-neutral-900 text-white dark:bg.white dark:text-neutral-900"
                              .replace(".white", "-white")
                            : "hover:bg-neutral-100 dark:hover:bg-neutral-800",
                        )}
                        onClick={() => setPage("myVoter")}
                      >
                        Vote
                      </button>
                      <button
                        className={cn(
                          "px-3 py-1 rounded-lg border text-sm dark:border-neutral-700",
                          page === "myCoord"
                            ? "bg-neutral-900 text-white dark:bg-white dark:text-neutral-900"
                            : "hover:bg-neutral-100 dark:hover:bg-neutral-800",
                        )}
                        onClick={() => setPage("myCoord")}
                      >
                        Coordinate
                      </button>
                    </nav>
                    <ThemeToggle />
                    <ZkAccountsButton onClick={() => setShowAccounts(true)} />
                    <WalletMultiButton />
                  </div>
                </header>

                {page === "create" && <PollCreator />}
                {page === "myVoter" && <MyVoterPolls />}
                {page === "myCoord" && <MyCoordinatorPolls />}

                <AccountDrawer
                  open={showAccounts}
                  onClose={() => setShowAccounts(false)}
                />
              </div>
            </div>
          </KeyringProvider>
        </WalletModalProvider>
      </WalletProvider>
    </ConnectionProvider>
  );
};

export default function App() {
  return <Inner />;
}
