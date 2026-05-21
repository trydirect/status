import { operatingModes } from "@/lib/site-content";

export function OperatingModes() {
  return (
    <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-5">
      {operatingModes.map((mode) => (
        <article
          key={mode.name}
          className="rounded-3xl border border-slate-200 bg-white p-5"
        >
          <p className="text-sm font-semibold text-emerald-700">
            {mode.label}
          </p>
          <h3 className="mt-3 text-lg font-semibold text-slate-950">
            {mode.name}
          </h3>
          <p className="mt-3 text-sm leading-6 text-slate-600">
            {mode.description}
          </p>
        </article>
      ))}
    </div>
  );
}
