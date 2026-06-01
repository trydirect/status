import { deploymentSteps } from "@/lib/site-content";

export function DeploymentTimeline() {
  return (
    <ol className="grid gap-5 lg:grid-cols-3">
      {deploymentSteps.map((step, index) => (
        <li
          key={step.title}
          className="rounded-3xl border border-slate-200 bg-white p-6"
        >
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-slate-950 text-sm font-semibold text-white">
            {index + 1}
          </div>
          <h3 className="mt-5 text-lg font-semibold text-slate-950">
            {step.title}
          </h3>
          <p className="mt-3 text-sm leading-6 text-slate-600">
            {step.description}
          </p>
        </li>
      ))}
    </ol>
  );
}
