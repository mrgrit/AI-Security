# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2017-05-12 02:51
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('aw', '0002_bl_wl'),
    ]

    operations = [
        migrations.AlterField(
            model_name='bl',
            name='flag',
            field=models.IntegerField(choices=[(1, 'Black List'), (2, 'White List'), (3, 'Holding')], default=3),
        ),
    ]
