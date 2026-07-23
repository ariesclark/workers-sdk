import { readFileSync } from "node:fs";
import { UserError } from "@cloudflare/workers-utils";
import { createCommand } from "../../../core/create-command";
import { logger } from "../../../logger";
import { requireAuth } from "../../../user";
import {
	deleteLocalInstances,
	getLocalInstanceIdFromArgs,
	localWorkflowArgs,
} from "../../local";
import { deleteInstances, getInstanceIdFromArgs } from "../../utils";
import type { WorkflowBatchDeleteResult } from "@cloudflare/workflows-shared/src/types";

export const workflowsInstancesDeleteCommand = createCommand({
	metadata: {
		description: "Delete workflow instances",
		owner: "Product: Workflows",
		status: "stable",
	},
	positionalArgs: ["name", "id"],
	args: {
		...localWorkflowArgs,
		name: {
			describe: "Name of the workflow",
			type: "string",
			demandOption: true,
		},
		id: {
			describe:
				"IDs of the instances - you can type 'latest' to get the latest instance and delete it",
			type: "string",
			array: true,
		},
		"ids-file": {
			describe: "Path to a file containing one instance ID per line",
			type: "string",
		},
	},

	async handler(args, { config }) {
		let fileIds: string[] = [];
		if (args.idsFile) {
			try {
				fileIds = readFileSync(args.idsFile, "utf8")
					.split(/\r?\n/)
					.map((id) => id.trim())
					.filter(Boolean);
			} catch (error) {
				throw new UserError(`Could not read IDs file "${args.idsFile}"`, {
					telemetryMessage: "workflows batch delete ids file unreadable",
					cause: error,
				});
			}
		}

		const requestedIds = [...(args.id ?? []), ...fileIds];
		if (requestedIds.length === 0) {
			throw new UserError("Provide at least one workflow instance ID", {
				telemetryMessage: "workflows batch delete no ids",
			});
		}
		if (requestedIds.length > 100) {
			throw new UserError(
				"You can delete at most 100 workflow instances at a time",
				{
					telemetryMessage: "workflows batch delete too large",
				}
			);
		}

		let ids: string[];
		let result: WorkflowBatchDeleteResult;

		if (args.local) {
			ids = await Promise.all(
				requestedIds.map((id) =>
					getLocalInstanceIdFromArgs(args.port, { id, name: args.name })
				)
			);
			result = await deleteLocalInstances(args.port, args.name, ids);
		} else {
			const accountId = await requireAuth(config);
			ids = await Promise.all(
				requestedIds.map((id) =>
					getInstanceIdFromArgs(accountId, { id, name: args.name }, config)
				)
			);
			result = await deleteInstances(config, accountId, args.name, ids);
		}

		if (result.deleted.length > 0) {
			logger.info(
				`🗑️  Deleted workflow instances from "${args.name}": ${result.deleted.map(({ id }) => `"${id}"`).join(", ")}`
			);
		}

		if (result.errors.length > 0) {
			throw new UserError(
				`Failed to delete ${result.errors.length} workflow instance(s):\n${result.errors.map(({ id, message }) => `  - ${id}: ${message}`).join("\n")}`,
				{ telemetryMessage: "workflows batch delete partial failure" }
			);
		}
	},
});
