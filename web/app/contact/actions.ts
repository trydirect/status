"use server";

import { submitContactMessage, type ContactFormState } from "@/lib/contact";

export async function submitContactAction(
  _previousState: ContactFormState,
  formData: FormData,
): Promise<ContactFormState> {
  return submitContactMessage(formData);
}
