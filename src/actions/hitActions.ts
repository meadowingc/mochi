import { db, Hit, and, eq, gte } from "astro:db";
import { defineAction } from "astro:actions";
import { z } from "astro:schema";

export const hits = {
  registerHit: defineAction({
    input: z.object({
      siteId: z.number(),
      date: z.date().optional(),
      path: z.string(),
      referer: z.string().optional(),
      visitorIpHash: z.string(),
      visitorUserAgentHash: z.string(),
      countryCode: z.string(),
    }),
    handler: async (input) => {
      input.date ||= new Date();

      // Insert the hit into the database
      const hit = await db
        .insert(Hit)
        .values({
          siteId: input.siteId,
          path: input.path,
          date: input.date,
          httpReferer: input.referer,
          visitorIpHash: input.visitorIpHash,
          visitorUserAgentHash: input.visitorUserAgentHash,
          countryCode: input.countryCode,
        })
        .execute();

      // should return bool
      return hit;
    },
  }),
  getHitsForSite: defineAction({
    input: z.object({
      siteId: z.number(),
      minDate: z.date().optional(),
    }),
    handler: async (input) => {
      // Get the hits from the database
      // default is 7 days ago

      const minDate = input.minDate
        ? new Date(input.minDate)
        : new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

      const hits = await db
        .select()
        .from(Hit)
        .where(and(eq(Hit.siteId, input.siteId), gte(Hit.date, minDate)));

      return hits;
    },
  }),
};
