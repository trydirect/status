import type { ReactNode } from "react";

interface SectionProps {
  id: string;
  eyebrow: string;
  title: string;
  description: string;
  children: ReactNode;
}

export function Section({
  id,
  eyebrow,
  title,
  description,
  children,
}: SectionProps) {
  return (
    <section id={id} className="border-b border-slate-200 bg-slate-50">
      <div className="mx-auto max-w-7xl px-6 py-20 sm:px-8 lg:px-12">
        <p className="text-sm font-semibold uppercase tracking-[0.2em] text-sky-700">
          {eyebrow}
        </p>
        <div className="mt-4 grid gap-6 lg:grid-cols-[0.9fr_1.1fr]">
          <h2 className="text-3xl font-semibold tracking-tight text-slate-950 sm:text-4xl">
            {title}
          </h2>
          <p className="text-lg leading-8 text-slate-600">{description}</p>
        </div>
        <div className="mt-12">{children}</div>
      </div>
    </section>
  );
}
