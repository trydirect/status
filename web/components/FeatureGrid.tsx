import { statusFeatures } from "@/lib/site-content";

export function FeatureGrid() {
  return (
    <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
      {statusFeatures.map((feature) => (
        <article
          key={feature.title}
          className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm transition hover:-translate-y-1 hover:shadow-xl hover:shadow-slate-200"
        >
          <div className="mb-5 inline-flex rounded-2xl bg-sky-50 px-3 py-2 text-sm font-semibold text-sky-800">
            {feature.label}
          </div>
          <h3 className="text-xl font-semibold text-slate-950">
            {feature.title}
          </h3>
          <p className="mt-3 leading-7 text-slate-600">{feature.description}</p>
        </article>
      ))}
    </div>
  );
}
