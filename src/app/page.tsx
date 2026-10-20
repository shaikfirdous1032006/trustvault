import { redirect } from "next/navigation";
import { getAuthenticatedUser } from "@/lib/auth";

export default async function Home() {
  try {
    const user = await getAuthenticatedUser();
    if (user) {
      redirect("/dashboard");
    }
  } catch {
    // If not authenticated, redirect to login
  }
  redirect("/login");
}
