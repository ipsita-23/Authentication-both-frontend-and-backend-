from django.db import models
class User(models.Model):
    username=models.CharField(max_length=100,unique=True)
    name=models.CharField(max_length=100)
    email=models.CharField(max_length=100,unique=True)
    password=models.CharField(max_length=128)
    

    def __str__(self):
        return self.name
# Create your models here.
