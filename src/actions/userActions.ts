import { defineAction } from "astro:actions";
import { Site, User, db, eq, and } from "astro:db";
import { z } from "astro:schema";

export const user = {
  getUserByEmail: defineAction({
    input: z.object({
      email: z.string(),
    }),
    handler: async (input) => {
      // Get the user from the database
      const user = await db
        .select()
        .from(User)
        .where(eq(User.email, input.email))
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
