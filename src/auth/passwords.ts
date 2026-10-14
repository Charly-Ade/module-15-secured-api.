import bcrypt from "bcrypt";
import crypto from "node:crypto";


export const BCRYPT_COST = 12;

export const hashPassword = (plain: string): Promise<string> => bcrypt.hash(plain, BCRYPT_COST);

export const verifyPassword = (plain: string, hash: string): Promise<boolean> =>
  bcrypt.compare(plain, hash);

let dummyHash: Promise<string> | undefined;

export const getDummyHash = (): Promise<string> =>
  (dummyHash ??= bcrypt.hash(crypto.randomUUID(), BCRYPT_COST));
