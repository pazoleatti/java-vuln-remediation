import semver from "semver";
import type { OsvVuln } from "./osv.js";
import { osvQueryBatch, vulnSummaries } from "./osv.js";
import {
  candidateUpgradeOrder,
  fetchMavenMetadataVersions,
  versionsNewerThan,
} from "./mavenMeta.js";

/** Prefer release builds (semver.parse — coerce обрезает prerelease у вида 3.0.0-beta3). */
function looksLikePreRelease(version: string): boolean {
  const p = semver.parse(version, true);
  if (p && p.prerelease.length > 0) return true;
  return /-SNAPSHOT$/i.test(version) || /-M\d+$/i.test(version);
}

function preferStableFirst(versions: string[]): string[] {
  const stable = versions.filter((v) => !looksLikePreRelease(v));
  const pre = versions.filter((v) => looksLikePreRelease(v));
  return [...stable, ...pre];
}

export type Remediation = {
  suggestedVersion: string | null;
  fixedVulnIds: string[];
  changeComment: string;
  triedVersions: string[];
};

function vulnIds(vulns: OsvVuln[] | undefined): Set<string> {
  return new Set((vulns ?? []).map((v) => v.id));
}

export async function suggestRemediation(
  groupId: string,
  artifactId: string,
  currentVersion: string,
  currentVulns: OsvVuln[] | undefined
): Promise<Remediation> {
  const oldIds = vulnIds(currentVulns);
  const oldSummaries = vulnSummaries(currentVulns);

  const meta = await fetchMavenMetadataVersions(groupId, artifactId);
  const tried: string[] = [];

  if (!meta?.versions.length) {
    return {
      suggestedVersion: null,
      fixedVulnIds: [...oldIds],
      changeComment:
        "Не удалось загрузить maven-metadata.xml с Maven Central (приватный репозиторий или неверные координаты). Рекомендуется проверить версию вручную.",
      triedVersions: tried,
    };
  }

  const { versions, release } = meta;
  const newerSlice = versionsNewerThan(versions, currentVersion);
  let order = preferStableFirst(candidateUpgradeOrder(newerSlice, versions));

  if (!order.length && release && release !== currentVersion) {
    order = preferStableFirst([release]);
  }

  const maxProbe = 40;
  for (const ver of order.slice(0, maxProbe)) {
    tried.push(ver);
    const batch = await osvQueryBatch([
      {
        package: { name: `${groupId}:${artifactId}`, ecosystem: "Maven" },
        version: ver,
      },
    ]);
    const nextVulns = batch.results[0]?.vulns ?? [];
    const nextIds = vulnIds(nextVulns);
    if (nextIds.size === 0) {
      const fixed = [...oldIds].filter((id) => !nextIds.has(id));
      const parts: string[] = [];
      if (fixed.length) {
        parts.push(`Сняты известные для текущей версии записи OSV: ${fixed.join(", ")}.`);
        for (const id of fixed.slice(0, 8)) {
          const s = oldSummaries.get(id);
          if (s) parts.push(`— ${id}: ${s}`);
        }
      } else {
        parts.push("Текущая версия не имела записей OSV для этого артефакта; целевая версия также чиста по OSV.");
      }
      parts.push(
        "Примечание: OSV не гарантирует полноту; для продакшена используйте OWASP Dependency-Check, Snyk или встроенные отчёты GitHub/GitLab."
      );
      return {
        suggestedVersion: ver,
        fixedVulnIds: fixed,
        changeComment: parts.join("\n"),
        triedVersions: tried,
      };
    }
  }

  return {
    suggestedVersion: null,
    fixedVulnIds: [...oldIds],
    changeComment:
      order.length === 0
        ? "Нет более новых версий в maven-metadata.xml на Maven Central относительно указанной."
        : `Проверено ${tried.length} более новых версий на Maven Central — по данным OSV уязвимости всё ещё присутствуют. Нужен ручной анализ или другой источник advisory.`,
    triedVersions: tried,
  };
}
