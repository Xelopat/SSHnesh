const { z } = require('zod/v4');

const uuid = z.uuid();
const binding = { sessionId: uuid, generation: uuid, grantId: uuid, requestId: uuid, expiresAt: z.int().positive() };
const schemas = {
  send: z.strictObject({ ...binding, text: z.string().min(1).max(2048).refine(
    text => !/[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(text), 'Ожидается одна строка без управляющих символов') }),
  output: z.strictObject({ ...binding, maxChars: z.int().min(1).max(4096) }),
  cancel: z.strictObject({ requestId: uuid }),
};

module.exports = { schemas };
