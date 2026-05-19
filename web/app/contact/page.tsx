import type { Metadata } from "next";
import Link from "next/link";
import { ContactForm } from "@/components/ContactForm";

export const metadata: Metadata = {
  title: "Contact",
  description:
    "Contact the Status Panel team about deployments, Stacker workflows, and infrastructure operations.",
};

export default function ContactPage() {
  return (
    <main className="min-h-screen bg-slate-50">
      <div className="mx-auto grid max-w-7xl gap-12 px-6 py-10 sm:px-8 lg:grid-cols-[0.85fr_1.15fr] lg:px-12 lg:py-16">
        <section className="rounded-3xl bg-slate-950 p-8 text-white shadow-xl">
          <Link href="/" className="text-sm font-medium text-sky-200">
            Back to home
          </Link>
          <h1 className="mt-12 text-4xl font-semibold tracking-tight sm:text-5xl">
            Plan a Status Panel deployment.
          </h1>
          <p className="mt-6 text-lg leading-8 text-slate-300">
            Tell us about your Stacker server, Status Panel scenario, or the
            Contact to Email Sender workflow you want to demonstrate.
          </p>
          <div className="mt-10 rounded-2xl border border-white/10 bg-white/10 p-5">
            <h2 className="text-base font-semibold">Pipe-ready by design</h2>
            <p className="mt-3 text-sm leading-6 text-slate-300">
              This form validates on the server and can later forward messages
              to a Stacker pipe when `CONTACT_PIPE_URL`, `CONTACT_PIPE_TOKEN`,
              and `CONTACT_TO_EMAIL` are configured.
            </p>
          </div>
        </section>
        <section className="rounded-3xl border border-slate-200 bg-white p-6 shadow-xl shadow-slate-200/70 sm:p-8">
          <ContactForm />
        </section>
      </div>
    </main>
  );
}
