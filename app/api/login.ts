import { NextApiRequest, NextApiResponse } from "next";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export default async function handler(
    req: NextApiRequest,
    res: NextApiResponse
) {
    if (req.method === "POST") {
        const { username, email, password } = req.body;

        try {
            const user = await prisma.profile.findFirst({
                where: {
                    username,
                    email,
                    passwordHash: password,
                },
            });

            if (user) {
                res
                    .status(200)
                    .json({ success: true, message: "Login successful", user });
            } else {
                res
                    .status(401)
                    .json({ success: false, message: "Invalid credentials" });
            }
        } catch (error) {
            console.error("Error during login:", error);
            res
                .status(500)
                .json({ success: false, message: "Internal Server Error" });
        }
    } else {
        res.status(405).json({ success: false, message: "Method Not Allowed" });
    }
}
