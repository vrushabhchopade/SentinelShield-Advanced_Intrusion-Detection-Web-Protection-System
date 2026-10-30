from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from apps.accounts.models import UserRole

User = get_user_model()

class AuthAndRolesTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user(
            username='admin_test',
            password='password123',
            role=UserRole.ADMIN
        )
        self.analyst = User.objects.create_user(
            username='analyst_test',
            password='password123',
            role=UserRole.ANALYST
        )
        self.viewer = User.objects.create_user(
            username='viewer_test',
            password='password123',
            role=UserRole.VIEWER
        )

    def test_user_role_properties(self):
        self.assertTrue(self.admin.is_admin_role)
        self.assertTrue(self.admin.is_analyst_role)

        self.assertFalse(self.analyst.is_admin_role)
        self.assertTrue(self.analyst.is_analyst_role)

        self.assertFalse(self.viewer.is_admin_role)
        self.assertFalse(self.viewer.is_analyst_role)

    def test_login_and_logout_flow(self):
        # Successful login
        response = self.client.post('/auth/login/', {
            'username': 'admin_test',
            'password': 'password123'
        })
        self.assertRedirects(response, '/dashboard/')

        # Logout
        logout_res = self.client.get('/auth/logout/')
        self.assertRedirects(logout_res, '/auth/login/')

    def test_invalid_login_rejected(self):
        response = self.client.post('/auth/login/', {
            'username': 'admin_test',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Invalid credentials')
