import { defineAction } from "astro:actions";
import { Site, User, db, eq, and } from "astro:db";
import { z } from "astro:schema";

export const site = {
  createSite: defineAction({
    input: z.object({
      userId: z.number(),
      url: z.string(),
    }),
    handler: async (input) => {
      // check that the user exists
      const user = await db
        .select()
        .from(User)
        .where(eq(User.id, input.userId))
        .limit(1);

      if (user.length === 0) {
        throw new Error("User not found");
      }

      // check that site doesn't already exist
      const site = await db
        .select()
        .from(Site)
        .where(and(eq(Site.userId, input.userId), eq(Site.url, input.url)))
        .limit(1);

      if (site.length > 0) {
        throw new Error("Site already exists");
      }

      // Create a site for the user
      await db.insert(Site).values({
        userId: input.userId,
        url: input.url,
        createdAt: new Date(),
      });
    },
  }),
  getSiteById: defineAction({
    input: z.object({
      siteId: z.number(),
    }),
    handler: async (input) => {
      // Get the site from the database
      const site = await db
        .select()
        .from(Site)
        .where(eq(Site.id, input.siteId))
        .limit(1);

      return site[0];
    },
  }),
};
