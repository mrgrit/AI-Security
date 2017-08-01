from django import forms
from.models import Log_full, IP_Cache, bl
from aw.choices import *
"""
class PostForm(forms.ModelForm):    

    class Meta:
        model = bl
        fields=('flag',)
"""
class BlForm(forms.Form):
    flag = forms.ChoiceField(choices = BL_CHOICES, label="",
                            initial='',
                            widget=forms.Select(),
                            required=True)
    
    

