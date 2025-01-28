import { defineAction } from "astro:actions";
import { User, db, eq } from "astro:db";
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
        await db.insert(User).values({ website: input.userWebsite });
      }
    },
  }),
};
