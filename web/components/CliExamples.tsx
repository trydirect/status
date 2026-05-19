import { cliExamples } from "@/lib/site-content";

export function CliExamples() {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      {cliExamples.map((example) => (
        <article
          key={example.command}
          className="rounded-2xl border border-slate-200 bg-white p-5"
        >
          <code className="block overflow-x-auto rounded-xl bg-slate-950 px-4 py-3 font-mono text-sm text-sky-100">
            {example.command}
          </code>
          <p className="mt-3 text-sm leading-6 text-slate-600">
            {example.description}
          </p>
        </article>
      ))}
    </div>
  );
}
