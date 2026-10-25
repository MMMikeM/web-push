import { defineCollection } from "astro:content";
import { docsLoader } from "@astrojs/starlight/loaders";
import { docsSchema } from "@astrojs/starlight/schema";
import { z } from "astro/zod";

export const collections = {
	docs: defineCollection({
		loader: docsLoader(),
		schema: docsSchema({
			extend: z.object({
				// Puts the runtime menu beside the title, for pages with runtime-specific steps.
				runtimePicker: z.boolean().optional(),
				// A phrase of the hero title to highlight. The title itself stays plain
				// text, because llms.txt prints it as it is.
				heroHighlight: z.string().optional(),
				// The hero's margin note, and the phrase of the tagline its arrow points at.
				heroNote: z.object({ text: z.string(), target: z.string() }).optional(),
			}),
		}),
	}),
};
