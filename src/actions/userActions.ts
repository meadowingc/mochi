import { defineAction } from "astro:actions";
import { Site, User, db, eq, and } from "astro:db";
import { z } from "astro:schema";

export const user = {
  ensureUserExists: defineAction({
    // Actions include type safety with Zod, removing the need
    // to check if typeof {value} === 'string' in your pages
    input: z.object({
      userWebsite: z.string(),
    }),
    handler: async (input) => {
      // Ensure the user exists in the database
      const user = await db
        .select()
        .from(User)
        .where(eq(User.website, input.userWebsite));

      if (user.length === 0) {
        // If the user doesn't exist, create them
        await db
          .insert(User)
          .values({ website: input.userWebsite, createdAt: new Date() });
      }
    },
  }),
  getUserByWebsite: defineAction({
    input: z.object({
      website: z.string(),
    }),
    handler: async (input) => {
      // Get the user from the database
      const user = await db
        .select()
        .from(User)
        .where(eq(User.website, input.website))
        .limit(1);

      return user[0];
    },
  }),
  getUserSites: defineAction({
    input: z.object({
      userId: z.number(),
    }),
    handler: async (input) => {
      // Get the user's sites from the database
      const sites = await db
        .select()
        .from(Site)
        .where(eq(Site.userId, input.userId));

      return sites;
    },
  }),
};
