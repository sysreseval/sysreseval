project = 'SRE / sysreseval'
author = 'IUT d\'Orsay, Université Paris-Saclay'
release = ''

extensions = ['myst_parser', 'sphinx.ext.graphviz']

# --- HTML --------------------------------------------------------------------

html_theme = 'furo'
html_title = 'SRE / sysreseval'
html_static_path = []
templates_path = ['_templates']

# --- MyST (Markdown) ---------------------------------------------------------

myst_enable_extensions = ['colon_fence', 'deflist', 'tasklist']
myst_heading_anchors = 3   # auto-generate slug anchors for h1..h3

# --- Graphviz ----------------------------------------------------------------

graphviz_output_format = 'svg'

# --- LaTeX / PDF -------------------------------------------------------------

latex_engine = 'xelatex'

# Suppress the auto-generated date on the title page (override \date *after*
# Sphinx's auto \date{...} by hooking \sphinxmaketitle).
latex_elements = {
    'maketitle': r'\date{}\sphinxmaketitle',
    'fontpkg':   r'',  # let xelatex pick fontspec defaults
    # ASCII fallbacks for unicode chars that lmmono10 lacks (used in
    # ASCII-art tree diagrams and the `sre watch` dashboard mock-up).
    'preamble': r'''
\usepackage{newunicodechar}
\newunicodechar{─}{-}
\newunicodechar{│}{|}
\newunicodechar{├}{+}
\newunicodechar{└}{+}
\newunicodechar{►}{>}
\newunicodechar{≤}{\ensuremath{\leq}}
''',
}

latex_documents = [
    ('index', 'sre.tex', 'SRE / sysreseval Documentation', author, 'manual'),
]
