import GitHub from "@auth/core/providers/github";
import { User, db, eq } from "astro:db";
import { defineConfig } from "auth-astro";

export default defineConfig({
  providers: [
    GitHub({
      clientId: import.meta.env.GITHUB_CLIENT_ID,
      clientSecret: import.meta.env.GITHUB_CLIENT_SECRET,
      profile: async (profile) => {
        // Actions include type safety with Zod, removing the need
        // to check if typeof {value} === 'string' in your pages
        // Ensure the user exists in the database
        let user = await db
          .select()
          .from(User)
          .where(eq(User.email, profile.email as string))
          .limit(1);

        if (user.length === 0) {
          // If the user doesn't exist, create them
          await db.insert(User).values({
            name: profile.name as string,
            email: profile.email as string,
            createdAt: new Date(),
          });
        }

        return {
          ...profile,
          id: profile.id.toString(),
        };
      },
    }),
  ],
});
