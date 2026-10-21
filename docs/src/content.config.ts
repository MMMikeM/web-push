import { defineCollection } from "astro:content";
import { docsLoader } from "@astrojs/starlight/loaders";
import { docsSchema } from "@astrojs/starlight/schema";
import { z } from "astro/zod";

export const collections = {
	docs: defineCollection({
		loader: docsLoader(),
		schema: docsSchema({
			// Puts the runtime menu beside the title, for pages with runtime-specific steps.
			extend: z.object({ runtimePicker: z.boolean().optional() }),
		}),
	}),
};
