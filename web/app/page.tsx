import Link from "next/link";
import { CliExamples } from "@/components/CliExamples";
import { DeploymentTimeline } from "@/components/DeploymentTimeline";
import { FeatureGrid } from "@/components/FeatureGrid";
import { OperatingModes } from "@/components/OperatingModes";
import { Section } from "@/components/Section";

export default function Home() {
  return (
    <main>
      <section className="relative overflow-hidden border-b border-slate-200 bg-slate-950 text-white">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(56,189,248,0.22),_transparent_32rem),radial-gradient(circle_at_bottom_right,_rgba(34,197,94,0.18),_transparent_28rem)]" />
        <div className="relative mx-auto flex min-h-[720px] max-w-7xl flex-col px-6 py-8 sm:px-8 lg:px-12">
          <nav className="flex items-center justify-between" aria-label="Primary">
            <Link href="/" className="text-lg font-semibold tracking-tight">
              Status Panel
            </Link>
            <div className="flex items-center gap-4 text-sm text-slate-300">
              <a href="#features" className="hover:text-white">
                Features
              </a>
              <a href="#cli" className="hover:text-white">
                CLI
              </a>
              <Link href="/contact" className="hover:text-white">
                Contact
              </Link>
            </div>
          </nav>

          <div className="grid flex-1 items-center gap-12 py-24 lg:grid-cols-[1.08fr_0.92fr]">
            <div>
              <p className="mb-5 inline-flex rounded-full border border-sky-300/30 bg-white/10 px-4 py-2 text-sm font-medium text-sky-100">
                Lightweight infrastructure agent for Stacker-managed servers
              </p>
              <h1 className="max-w-4xl text-5xl font-semibold tracking-tight sm:text-6xl lg:text-7xl">
                Operate containers, metrics, logs, and deployments from one
                secure panel.
              </h1>
              <p className="mt-8 max-w-2xl text-lg leading-8 text-slate-300">
                Status Panel is a single-binary operations agent for health
                checks, Docker/container management, system metrics, signed
                remote commands, Vault-backed configuration, and Stacker
                deployment workflows.
              </p>
              <div className="mt-10 flex flex-col gap-4 sm:flex-row">
                <Link
                  href="/contact"
                  className="rounded-full bg-sky-400 px-6 py-3 text-center text-sm font-semibold text-slate-950 shadow-lg shadow-sky-950/30 transition hover:bg-sky-300"
                >
                  Talk to us
                </Link>
                <a
                  href="#deployment"
                  className="rounded-full border border-white/20 px-6 py-3 text-center text-sm font-semibold text-white transition hover:bg-white/10"
                >
                  See deployment flow
                </a>
              </div>
            </div>

            <div className="rounded-3xl border border-white/10 bg-white/10 p-5 shadow-2xl shadow-slate-950/40 backdrop-blur">
              <div className="rounded-2xl bg-slate-950 p-5 font-mono text-sm text-slate-100">
                <div className="mb-4 flex gap-2">
                  <span className="h-3 w-3 rounded-full bg-red-400" />
                  <span className="h-3 w-3 rounded-full bg-yellow-300" />
                  <span className="h-3 w-3 rounded-full bg-emerald-400" />
                </div>
                <pre className="whitespace-pre-wrap leading-7">
                  <code>{`$ status health
ok: nginx, api, postgres

$ status metrics --json
{"cpu":18.4,"memory":42.1,"disk":61.9}

$ stacker deploy --target cloud
plan: web -> firewall -> proxy -> verify`}</code>
                </pre>
              </div>
            </div>
          </div>
        </div>
      </section>

      <Section
        id="features"
        eyebrow="Operations capabilities"
        title="Everything needed to inspect and control a Stacker server."
        description="Status Panel keeps day-two operations close to the server while preserving signed, auditable control from Stacker."
      >
        <FeatureGrid />
      </Section>

      <Section
        id="cli"
        eyebrow="CLI quickstart"
        title="Use the same binary for local checks, API mode, and remote agent workflows."
        description="The command surface is intentionally small enough for operators and automation to share."
      >
        <CliExamples />
      </Section>

      <Section
        id="modes"
        eyebrow="Operating modes"
        title="Choose the runtime shape that matches the server."
        description="Run one-off commands locally, expose a JSON API, enable the bundled UI, or let Stacker drive long-polling agent execution."
      >
        <OperatingModes />
      </Section>

      <Section
        id="deployment"
        eyebrow="This site as a deployment demo"
        title="Built locally, deployed with Stacker, verified through Status Panel."
        description="The same website you are reading is designed to become the end-to-end example for Stacker CLI, Stacker MCP, Status Panel, firewall, Nginx Proxy Manager, and future pipes."
      >
        <DeploymentTimeline />
      </Section>
    </main>
  );
}
