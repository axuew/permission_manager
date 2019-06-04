from . import filters


class flask_perms(object):
    def __init__(self, app=None, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

        if app:
            self.init_app(app)

    def init_app(self, app):
        app.add_template_filter(filters.perm_check)



