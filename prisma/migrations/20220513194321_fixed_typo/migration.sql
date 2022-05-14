/*
  Warnings:

  - You are about to drop the column `refresToken` on the `user` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "user" DROP COLUMN "refresToken",
ADD COLUMN     "refreshToken" TEXT;
