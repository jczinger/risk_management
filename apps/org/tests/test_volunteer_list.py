"""
The volunteer list's pager.

Regression coverage for a quiet filter reset: the pager links used to be a bare
``?page=N``, which replaces the whole querystring — so paging a filtered list
silently dropped the name/department/status filters and page 2 showed everyone.
"""

from __future__ import annotations

from django.urls import reverse

from apps.core.tests.base import TenantTestCase
from apps.org.views import PAGE_SIZE


class PagerKeepsFiltersTests(TenantTestCase):
    def setUp(self):
        super().setUp()
        self.seed()
        self.childrens = self.make_department("Children's Ministry")
        self.kitchen = self.make_department("Kitchen")
        self.teacher = self.make_role(self.childrens, name="Teacher")
        self.cook = self.make_role(self.kitchen, name="Cook")

        # Enough volunteers in one department to force a second page.
        for i in range(PAGE_SIZE + 1):
            volunteer = self.make_volunteer(first_name=f"Kid{i:02d}", last_name="Helper")
            self.assign(volunteer, self.teacher)
        self.assign(self.make_volunteer(first_name="Solo", last_name="Cook"), self.cook)

        self.client = self.signed_in_client()

    def test_the_pager_links_carry_the_active_filters(self):
        response = self.client.get(
            reverse("org:volunteer_list"), {"department": self.childrens.pk}
        )
        body = response.content.decode()
        self.assertIn(f"department={self.childrens.pk}&amp;page=2", body)

    def test_page_two_of_a_filtered_list_stays_filtered(self):
        response = self.client.get(
            reverse("org:volunteer_list"),
            {"department": self.childrens.pk, "page": 2},
        )
        body = response.content.decode()
        self.assertNotIn("Solo", body)
        # The pager on page 2 keeps the filter too, pointing back at page 1.
        self.assertIn(f"department={self.childrens.pk}&amp;page=1", body)
