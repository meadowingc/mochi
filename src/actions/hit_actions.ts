import { db, AnalyticsHit } from "astro:db";
import { defineAction } from "astro:actions";
import { z } from "astro:schema";

export const hits = {
  addComment: defineAction({
    // Actions include type safety with Zod, removing the need
    // to check if typeof {value} === 'string' in your pages
    input: z.object({
      author: z.string(),
      body: z.string(),
    }),
    handler: async (input) => {
      const updatedComments = await db
        .insert(AnalyticsHit)
        .values(input)
        .returning(); // Return the updated comments
      return updatedComments;
    },
  }),
};
