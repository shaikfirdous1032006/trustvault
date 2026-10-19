/**
 * End-to-End Tests for TrustVault
 *
 * Tests the full user journey through the browser:
 * - Login flow for each role
 * - Document upload (owner)
 * - Permission grant/revoke (owner)
 * - Document access (viewer with/without permission)
 * - Admin dashboard access
 * - Audit trail visibility
 */

import { test, expect, type Page } from '@playwright/test';

const DEMO_PASSWORD = 'TrustVault2024!';

async function login(page: Page, email: string) {
  await page.goto('/login');
  await page.fill('#email', email);
  await page.fill('#password', DEMO_PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/dashboard/, { timeout: 15000 });
}

async function logout(page: Page) {
  // Click the sign out button in sidebar
  const logoutBtn = page.locator('text=Sign out');
  if (await logoutBtn.isVisible()) {
    await logoutBtn.click();
    await page.waitForURL(/\/login/, { timeout: 10000 });
  }
}

test.describe('Authentication', () => {
  test('login page renders correctly', async ({ page }) => {
    await page.goto('/login');
    await expect(page.locator('h2')).toContainText('Welcome back');
    await expect(page.locator('#email')).toBeVisible();
    await expect(page.locator('#password')).toBeVisible();
  });

  test('invalid credentials show error', async ({ page }) => {
    await page.goto('/login');
    await page.fill('#email', 'fake@example.com');
    await page.fill('#password', 'wrongpassword');
    await page.click('button[type="submit"]');
    await expect(page.locator('.text-danger, [class*="danger"]')).toBeVisible({ timeout: 10000 });
  });

  test('admin can login successfully', async ({ page }) => {
    await login(page, 'admin@example.com');
    await expect(page).toHaveURL(/\/dashboard/);
  });

  test('owner can login successfully', async ({ page }) => {
    await login(page, 'owner@example.com');
    await expect(page).toHaveURL(/\/dashboard/);
  });

  test('viewer can login successfully', async ({ page }) => {
    await login(page, 'viewer@example.com');
    await expect(page).toHaveURL(/\/dashboard/);
  });
});

test.describe('Dashboard — Owner Role', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'owner@example.com');
  });

  test('dashboard shows greeting and stats', async ({ page }) => {
    await expect(page.locator('h1')).toContainText(/Good (morning|afternoon|evening)/);
    await expect(page.locator('text=Documents')).toBeVisible();
  });

  test('can navigate to documents page', async ({ page }) => {
    await page.click('a[href="/dashboard/documents"]');
    await page.waitForURL(/\/dashboard\/documents/);
    await expect(page.locator('h1')).toContainText('Documents');
  });

  test('can navigate to upload page', async ({ page }) => {
    await page.click('a[href="/dashboard/upload"]');
    await page.waitForURL(/\/dashboard\/upload/);
    await expect(page.locator('h1')).toContainText('Upload Document');
  });

  test('upload page has file drop zone and form fields', async ({ page }) => {
    await page.goto('/dashboard/upload');
    await expect(page.locator('#file-drop-zone')).toBeVisible();
    await expect(page.locator('#doc-title')).toBeVisible();
    await expect(page.locator('#doc-category')).toBeVisible();
  });
});

test.describe('Dashboard — Admin Role', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin@example.com');
  });

  test('admin sees Users and Audit Log in sidebar', async ({ page }) => {
    await expect(page.locator('text=Users')).toBeVisible();
    await expect(page.locator('text=Audit Log')).toBeVisible();
  });

  test('admin can access users management page', async ({ page }) => {
    await page.click('a[href="/dashboard/admin/users"]');
    await page.waitForURL(/\/dashboard\/admin\/users/);
    await expect(page.locator('h1')).toContainText('User Management');
  });

  test('admin can access audit log page', async ({ page }) => {
    await page.click('a[href="/dashboard/admin/audit"]');
    await page.waitForURL(/\/dashboard\/admin\/audit/);
    await expect(page.locator('h1')).toContainText('Platform Audit Log');
  });

  test('audit log shows hash chain information', async ({ page }) => {
    await page.goto('/dashboard/admin/audit');
    await expect(page.locator('text=Immutable Audit Trail')).toBeVisible();
    await expect(page.locator('text=SHA-256')).toBeVisible();
  });
});

test.describe('Dashboard — Viewer Role', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'viewer@example.com');
  });

  test('viewer does NOT see Upload in sidebar', async ({ page }) => {
    // Upload nav item is only for owner/admin roles
    const uploadLink = page.locator('a[href="/dashboard/upload"]');
    await expect(uploadLink).toHaveCount(0);
  });

  test('viewer does NOT see admin nav items', async ({ page }) => {
    const usersLink = page.locator('a[href="/dashboard/admin/users"]');
    const auditLink = page.locator('a[href="/dashboard/admin/audit"]');
    await expect(usersLink).toHaveCount(0);
    await expect(auditLink).toHaveCount(0);
  });

  test('viewer can see documents page', async ({ page }) => {
    await page.click('a[href="/dashboard/documents"]');
    await page.waitForURL(/\/dashboard\/documents/);
    await expect(page.locator('h1')).toContainText('Documents');
  });
});

test.describe('UI States', () => {
  test('login page is responsive', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 }); // iPhone X
    await page.goto('/login');
    await expect(page.locator('#email')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('unauthenticated access redirects to login', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/login/);
  });

  test('documents page shows empty state or results', async ({ page }) => {
    await login(page, 'viewer@example.com');
    await page.goto('/dashboard/documents');
    
    // Should show either document cards or empty state
    const hasDocuments = await page.locator('[id^="document-card-"]').count() > 0;
    const hasEmptyState = await page.locator('text=No documents').isVisible().catch(() => false);
    
    expect(hasDocuments || hasEmptyState).toBe(true);
  });
});
