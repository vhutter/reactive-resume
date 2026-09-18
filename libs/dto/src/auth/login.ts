import { createZodDto } from "nestjs-zod/dto";
import { z } from "nestjs-zod/z";

import { usernameSchema } from "../user";

export const loginSchema = z
  .object({
    identifier: z.string(),
    // 5, not 6, so the default `vince` / `vince` account can be used manually.
    password: z.password().min(5),
  })
  .refine(
    (value) => {
      return value.identifier.includes("@")
        ? z.string().email().parse(value.identifier)
        : usernameSchema.parse(value.identifier);
    },
    { message: "InvalidCredentials" },
  );

export class LoginDto extends createZodDto(loginSchema) {}
