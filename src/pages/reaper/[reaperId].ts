export const prerender = false;

export async function GET({ params, url: rawUrl, ...request }) {
  // http://localhost:4321/reaper/34?url=${current_url}&path=${path}&referrer=${referrer}
  const { reaperId } = params;

  const url = new URL(rawUrl);
  const current_url = url.searchParams.get("url");
  const path = url.searchParams.get("path");
  const referrer = url.searchParams.get("referrer");

  return new Response(
    JSON.stringify({
      message: `This is my dynamic endpoint with id ${reaperId}, and ${JSON.stringify(
        request
      )}, ${current_url}, ${path}, ${referrer}`,
    })
  );
}
