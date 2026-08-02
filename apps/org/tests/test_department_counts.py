"""
Pins for the department counts, which moved from per-row properties to annotations.

Two ``Count(distinct=True)`` annotations over different join paths is exactly where
Django silently over-counts when a ``distinct`` is dropped, and the failure only
appears once a real church has a volunteer holding two roles in one department — so
that case is pinned here.
"""

from __future__ import annotations

from django.urls import reverse

from apps.core.tests.base import TenantTestCase
from apps.reporting.services import build_department_summary


class DepartmentCountsTests(TenantTestCase):
    def setUp(self):
        super().setUp()
        self.seed()
        self.childrens = self.make_department("Children's Ministry")
        self.teacher = self.make_role(self.childrens, name="Teacher")
        self.helper = self.make_role(self.childrens, name="Helper")

        # One volunteer holding BOTH roles in the same department — must count once.
        self.double = self.make_volunteer(first_name="Both", last_name="Roles")
        self.assign(self.double, self.teacher)
        self.assign(self.double, self.helper)

        self.single = self.make_volunteer(first_name="One", last_name="Role")
        self.assign(self.single, self.teacher)

        self.client = self.signed_in_client()

    def test_the_department_list_counts_a_two_role_volunteer_once(self):
        response = self.client.get(reverse("org:department_list"))
        department = next(
            d for d in response.context["departments"] if d.pk == self.childrens.pk
        )
        self.assertEqual(department.role_count, 2)
        self.assertEqual(department.volunteer_count, 2)

    def test_the_department_summary_counts_a_two_role_volunteer_once(self):
        summary = next(
            row
            for row in build_department_summary()
            if row["department"].pk == self.childrens.pk
        )
        self.assertEqual(summary["volunteers"], 2)
        # Each volunteer's instances count once for the department, however many
        # roles they hold in it.
        instance_count = self.double.requirement_instances.filter(
            definition__is_active=True
        ).count() + self.single.requirement_instances.filter(definition__is_active=True).count()
        self.assertEqual(summary["requirements"], instance_count)

    def test_a_volunteer_serving_two_departments_counts_in_both_summaries(self):
        kitchen = self.make_department("Kitchen")
        cook = self.make_role(kitchen, name="Cook")
        self.assign(self.single, cook)

        rows = {row["department"].pk: row for row in build_department_summary()}
        self.assertEqual(rows[self.childrens.pk]["volunteers"], 2)
        self.assertEqual(rows[kitchen.pk]["volunteers"], 1)
        # The same instances appear under both departments the volunteer serves.
        single_instances = self.single.requirement_instances.filter(
            definition__is_active=True
        ).count()
        self.assertEqual(rows[kitchen.pk]["requirements"], single_instances)
