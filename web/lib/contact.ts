import { z } from "zod";

export const contactSchema = z.object({
  name: z.string().trim().min(2, "Enter at least 2 characters.").max(80),
  email: z.email("Enter a valid email address.").max(254),
  subject: z.string().trim().min(4, "Enter at least 4 characters.").max(120),
  message: z
    .string()
    .trim()
    .min(20, "Enter at least 20 characters.")
    .max(4000),
});

export type ContactPayload = z.infer<typeof contactSchema>;

export interface ContactFormState {
  ok: boolean;
  status: "idle" | "validation_error" | "configuration_pending" | "sent";
  message?: string;
  fieldErrors?: Partial<Record<keyof ContactPayload, string[]>>;
}

export const initialContactFormState: ContactFormState = {
  ok: false,
  status: "idle",
};

export async function submitContactMessage(
  formData: FormData,
): Promise<ContactFormState> {
  const parsed = contactSchema.safeParse({
    name: formData.get("name"),
    email: formData.get("email"),
    subject: formData.get("subject"),
    message: formData.get("message"),
  });

  if (!parsed.success) {
    return {
      ok: false,
      status: "validation_error",
      message: "Please fix the highlighted fields.",
      fieldErrors: parsed.error.flatten().fieldErrors,
    };
  }

  const pipeUrl = process.env.CONTACT_PIPE_URL;
  const pipeToken = process.env.CONTACT_PIPE_TOKEN;
  const toEmail = process.env.CONTACT_TO_EMAIL;

  if (!pipeUrl || !pipeToken || !toEmail) {
    return {
      ok: true,
      status: "configuration_pending",
      message:
        "Message validated. The email pipe is not configured yet, so delivery is pending deployment wiring.",
    };
  }

  const response = await fetch(pipeUrl, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${pipeToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      to: toEmail,
      source: "status-panel-web",
      payload: parsed.data,
    }),
    cache: "no-store",
  });

  if (!response.ok) {
    return {
      ok: false,
      status: "validation_error",
      message: `The contact pipe rejected the message with HTTP ${response.status}.`,
    };
  }

  return {
    ok: true,
    status: "sent",
    message: "Message accepted by the configured Stacker pipe.",
  };
}
