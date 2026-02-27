from django.shortcuts import render, get_object_or_404, redirect
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView, TemplateView
from django.urls import reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm
from django import forms
from django.contrib.auth import get_user_model, authenticate, login
from .models import Entry, Tag, Favorite
from django.db.models import Q
from django.contrib.auth.views import LoginView as DjangoLoginView

class CustomLoginView(DjangoLoginView):
    template_name = 'registration/login.html'
    
    def form_valid(self, form):
        """
        Handle successful form submission.
        We ensure that login() is called correctly with our custom user.
        """
        username = form.cleaned_data.get('username')
        password = form.cleaned_data.get('password')
        
        user = authenticate(self.request, username=username, password=password)
        if user is not None:
            login(self.request, user)
            return redirect(self.get_success_url())
        else:
            return self.form_invalid(form)

class EntryListView(ListView):
    model = Entry
    template_name = 'core/entry_list.html'
    context_object_name = 'entries'
    paginate_by = 10
    
    def get_queryset(self):
        queryset = Entry.objects.all().order_by('-created_at')
        
        # Filter by search query
        search_query = self.request.GET.get('q')
        if search_query:
            queryset = queryset.filter(
                Q(title__icontains=search_query) | 
                Q(body__icontains=search_query) | 
                Q(tags__value__icontains=search_query)
            ).distinct()
        
        # Filter by tag
        tag_slug = self.request.GET.get('tag')
        if tag_slug:
            queryset = queryset.filter(tags__value=tag_slug)
        
        return queryset

class EntryDetailView(DetailView):
    model = Entry
    template_name = 'core/entry_detail.html'
    context_object_name = 'entry'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        entry = self.get_object()
        
        # Check if favorited
        if self.request.user.is_authenticated:
            context['is_favorited'] = Favorite.objects.filter(
                user=self.request.user, 
                entry=entry
            ).exists()
        else:
            context['is_favorited'] = False
            
        return context

class EntryCreateView(LoginRequiredMixin, CreateView):
    model = Entry
    template_name = 'core/entry_form.html'
    fields = ['title', 'body', 'shared', 'tags']
    success_url = reverse_lazy('entry-list')
    
    def form_valid(self, form):
        form.instance.author = self.request.user
        return super().form_valid(form)

class EntryUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = Entry
    template_name = 'core/entry_form.html'
    fields = ['title', 'body', 'shared', 'tags']
    
    def test_func(self):
        entry = self.get_object()
        return self.request.user == entry.author
    
    def get_success_url(self):
        return reverse_lazy('entry-detail', kwargs={'pk': self.object.pk})

class EntryDeleteView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
    model = Entry
    template_name = 'core/entry_confirm_delete.html'
    success_url = reverse_lazy('entry-list')
    
    def test_func(self):
        entry = self.get_object()
        return self.request.user == entry.author

class TagListView(ListView):
    model = Tag
    template_name = 'core/tag_list.html'
    context_object_name = 'tags'
    paginate_by = 20

class TagDetailView(DetailView):
    model = Tag
    template_name = 'core/tag_detail.html'
    context_object_name = 'tag'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        tag = self.get_object()
        context['entries'] = Entry.objects.filter(tags=tag).order_by('-created_at')
        return context

class TagCreateView(LoginRequiredMixin, CreateView):
    model = Tag
    template_name = 'core/tag_form.html'
    fields = ['value']
    success_url = reverse_lazy('tag-list')

class TagUpdateView(LoginRequiredMixin, UpdateView):
    model = Tag
    template_name = 'core/tag_form.html'
    fields = ['value']
    success_url = reverse_lazy('tag-list')

class TagDeleteView(LoginRequiredMixin, DeleteView):
    model = Tag
    template_name = 'core/tag_confirm_delete.html'
    success_url = reverse_lazy('tag-list')

@login_required
def toggle_favorite(request, entry_id):
    entry = get_object_or_404(Entry, pk=entry_id)
    favorite, created = Favorite.objects.get_or_create(user=request.user, entry=entry)
    
    if not created:
        favorite.delete()
        messages.success(request, f'Removed {entry.title} from favorites')
    else:
        messages.success(request, f'Added {entry.title} to favorites')
    
    return redirect('entry-detail', pk=entry_id)

@login_required
def user_favorites(request):
    favorites = Favorite.objects.filter(user=request.user).select_related('entry').order_by('-created_at')
    return render(request, 'core/favorites.html', {'favorites': favorites})


class APIDocumentationView(TemplateView):
    """
    API Documentation view
    """
    template_name = 'api_docs.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['api_base_url'] = self.request.build_absolute_uri('/api/')
        return context


class CustomUserCreationForm(forms.ModelForm):
    """
    Custom user creation form that works with our custom User model
    """
    password1 = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        help_text="Enter a strong password",
    )
    password2 = forms.CharField(
        label="Password confirmation",
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
        strip=False,
        help_text="Enter the same password as before, for verification.",
    )
    
    class Meta:
        model = get_user_model()
        fields = ('username', 'email')
        help_texts = {
            'username': None,  # Remove default username help text
        }
    
    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(
                self.error_messages['password_mismatch'],
                code='password_mismatch',
            )
        return password2
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user
    
    error_messages = {
        'password_mismatch': 'The two password fields didn’t match.',
    }


class RegisterView(CreateView):
    """
    User registration view
    """
    form_class = CustomUserCreationForm
    template_name = 'registration/register.html'
    success_url = reverse_lazy('login')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Register'
        return context


class ProfileView(LoginRequiredMixin, TemplateView):
    """
    User profile view - redirects to user's entries
    """
    template_name = 'core/profile.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        
        # Get user's entries
        context['user_entries'] = Entry.objects.filter(author=user).order_by('-created_at')[:10]
        
        # Get user's favorites
        context['user_favorites'] = Favorite.objects.filter(user=user).select_related('entry').order_by('-created_at')[:10]
        
        return context


class CustomLogoutView(TemplateView):
    """
    Custom logout view that handles both GET and POST requests
    """
    template_name = 'registration/logout.html'
    
    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            from django.contrib.auth import logout
            logout(request)
        return super().get(request, *args, **kwargs)