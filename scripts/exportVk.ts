import { formatVk } from "../helpers/exportSolana.ts";

async function main(): Promise<void> {
  console.log(
    "pub const VK_VOTE: Groth16Verifyingkey =",
    formatVk("./build/Vote/groth16_vkey.json"),
  );
  console.log();
  console.log(
    "pub const VK_TALLY: Groth16Verifyingkey =",
    formatVk("./build/Tally/groth16_vkey.json"),
  );
  console.log();
  console.log(
    "pub const VK_RELAY: Groth16Verifyingkey =",
    formatVk("./build/Relay/groth16_vkey.json"),
  );
}

main();
