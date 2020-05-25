from setuptools import find_packages
from setuptools import setup

setup(
    name='svs',
    version='1.0.1',
    description='The InAcademia Simple validation Service allows for the easy validation of affiliation (Student,'
                'Faculty, Staff) of a user in Academia',
    license='Apache 2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
    ],
    author='Rebecka Gulliksson',
    author_email='tech@inacademia.org',
    zip_safe=False,
    url='http://www.inacademia.org',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    package_data={
        'svs': [
            'data/i18n/locale/*/LC_MESSAGES/*.mo',
            'templates/*.mako',
            'site/static/*',
            'util/*',
        ],
    },
    message_extractors={
        'src/svs': [
            ('**.py', 'python', None),
            ('templates/**.mako', 'mako', None),
            ('site/**', 'ignore', None)
        ]
    },
    install_requires=[
        'satosa==3.4.8',
        'Mako',
        'gunicorn',
        'Werkzeug'
    ]
)
