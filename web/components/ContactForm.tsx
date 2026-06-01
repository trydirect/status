"use client";

import { useActionState } from "react";
import { submitContactAction } from "@/app/contact/actions";
import { initialContactFormState } from "@/lib/contact";

export function ContactForm() {
  const [state, formAction, isPending] = useActionState(
    submitContactAction,
    initialContactFormState,
  );

  return (
    <form action={formAction} className="space-y-6" noValidate>
      <div>
        <p className="text-sm font-semibold uppercase tracking-[0.2em] text-sky-700">
          Contact
        </p>
        <h2 className="mt-3 text-3xl font-semibold tracking-tight text-slate-950">
          Tell us what you want to deploy.
        </h2>
      </div>

      {state.message ? (
        <div
          className={`rounded-2xl border px-4 py-3 text-sm ${
            state.ok
              ? "border-emerald-200 bg-emerald-50 text-emerald-900"
              : "border-red-200 bg-red-50 text-red-900"
          }`}
          role="status"
        >
          {state.message}
        </div>
      ) : null}

      <Field
        label="Name"
        name="name"
        autoComplete="name"
        error={state.fieldErrors?.name?.[0]}
      />
      <Field
        label="Email"
        name="email"
        type="email"
        autoComplete="email"
        error={state.fieldErrors?.email?.[0]}
      />
      <Field
        label="Subject"
        name="subject"
        error={state.fieldErrors?.subject?.[0]}
      />
      <div>
        <label
          htmlFor="message"
          className="block text-sm font-medium text-slate-800"
        >
          Message
        </label>
        <textarea
          id="message"
          name="message"
          rows={7}
          className="mt-2 w-full rounded-2xl border border-slate-300 px-4 py-3 text-slate-950 shadow-sm outline-none transition focus:border-sky-500 focus:ring-4 focus:ring-sky-100"
          aria-invalid={Boolean(state.fieldErrors?.message)}
          aria-describedby={
            state.fieldErrors?.message ? "message-error" : undefined
          }
        />
        {state.fieldErrors?.message?.[0] ? (
          <p id="message-error" className="mt-2 text-sm text-red-700">
            {state.fieldErrors.message[0]}
          </p>
        ) : null}
      </div>

      <button
        type="submit"
        disabled={isPending}
        className="w-full rounded-full bg-slate-950 px-6 py-3 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:bg-slate-400"
      >
        {isPending ? "Sending..." : "Send message"}
      </button>
    </form>
  );
}

interface FieldProps {
  label: string;
  name: "name" | "email" | "subject";
  type?: string;
  autoComplete?: string;
  error?: string;
}

function Field({
  label,
  name,
  type = "text",
  autoComplete,
  error,
}: FieldProps) {
  const errorId = `${name}-error`;

  return (
    <div>
      <label htmlFor={name} className="block text-sm font-medium text-slate-800">
        {label}
      </label>
      <input
        id={name}
        name={name}
        type={type}
        autoComplete={autoComplete}
        className="mt-2 w-full rounded-2xl border border-slate-300 px-4 py-3 text-slate-950 shadow-sm outline-none transition focus:border-sky-500 focus:ring-4 focus:ring-sky-100"
        aria-invalid={Boolean(error)}
        aria-describedby={error ? errorId : undefined}
      />
      {error ? (
        <p id={errorId} className="mt-2 text-sm text-red-700">
          {error}
        </p>
      ) : null}
    </div>
  );
}
