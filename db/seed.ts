import { db, Site, User } from "astro:db";

export default async function () {
  await db.insert(User).values([
    {
      id: 1,
      name: "Meadow",
      email: "meadowingc@proton.me",
      createdAt: new Date(),
    },
  ]);

  await db.insert(Site).values([
    {
      id: 1,
      userId: 1,
      url: "https://meadow.cafe",
      createdAt: new Date(),
    },
  ]);
}
