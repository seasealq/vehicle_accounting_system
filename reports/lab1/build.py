from pathlib import Path
import re
root=Path(__file__).resolve().parents[2]
src=(root/'МостоваяПОлаба1.md').read_text().splitlines()
out=[]
# The original Markdown remains the authoritative source; this file is only its print layout.
head=r'''\documentclass[12pt,a4paper]{article}
\usepackage{fontspec}
\usepackage{polyglossia}
\setdefaultlanguage{russian}
\setmainfont{STIX Two Text}
\setmonofont{Menlo}
\newfontfamily\cyrillicfonttt{Menlo}
\usepackage[a4paper,margin=2cm]{geometry}
\usepackage{graphicx,longtable,tabularx,array,booktabs}
\usepackage{enumitem,xurl,listings,hyperref}
\hypersetup{colorlinks=true,linkcolor=blue,urlcolor=blue}
\lstset{basicstyle=\ttfamily\footnotesize,breaklines=true,columns=fullflexible,frame=single,keepspaces=true,showstringspaces=false}
\setlength{\parindent}{1.25cm}
\setlength{\parskip}{0.25em}
\renewcommand{\arraystretch}{1.16}
\setlist{nosep,leftmargin=1.5em}
\sloppy
\begin{document}
\begin{titlepage}
\centering
{\large Лабораторная работа № 1\par}
\vspace{2.5cm}
{\LARGE\bfseries Подготовка среды разработки и репозитория защищённого программного проекта\par}
\vspace{1.8cm}
\begin{tabular}{p{4cm}p{11cm}}
Дисциплина: & Основы разработки защищённого программного обеспечения и компьютерных сетей\\
Вариант: & 19 — Система учёта транспортных средств организации\\
Версия сквозного проекта: & v0.1\\
Студент: & Мостовая Полина Андреевна\\
Группа: & ИУСбд-02-23
\end{tabular}
\vfill
{\large 2026\par}
\end{titlepage}
\tableofcontents
\clearpage
'''

def esc(s):
    s=s.replace('\\','\\textbackslash{}')
    for a,b in [('&',r'\&'),('%',r'\%'),('$',r'\$'),('#',r'\#'),('_',r'\_'),('{',r'\{'),('}',r'\}')]: s=s.replace(a,b)
    s=s.replace('→',r'$\rightarrow$')
    return s

def inline(s):
    # Protect code and bold while escaping remaining text.
    parts=re.split(r'(`[^`]*`|\*\*[^*]+\*\*)',s)
    out=[]
    for z in parts:
        if z.startswith('`') and z.endswith('`'):
            val=z[1:-1].replace('\\',r'\textbackslash{}').replace('_',r'\_').replace('%',r'\%').replace('#',r'\#').replace('/',r'/\allowbreak{}').replace('.',r'.\allowbreak{}')
            out.append(r'\texttt{'+val+'}')
        elif z.startswith('**') and z.endswith('**'):
            out.append(r'\textbf{'+esc(z[2:-2])+'}')
        else: out.append(esc(z))
    return ''.join(out)

# Skip Markdown title block; represented by a typeset cover above.
i=0
while i<len(src) and src[i].strip()!='---': i+=1
i+=1
para=[]; list_kind=None; code=False; code_lines=[]
def flush_para():
    global para
    if para:
        out.append(inline(' '.join(x.strip() for x in para)))
        out.append('')
        para=[]
def close_list():
    global list_kind
    if list_kind:
        out.append(r'\end{'+list_kind+'}')
        list_kind=None
while i<len(src):
    line=src[i]; st=line.strip()
    if st.startswith('```'):
        flush_para(); close_list()
        if not code: out.append(r'\begin{lstlisting}'); code=True; code_lines=[]
        else: out.extend(code_lines); out.append(r'\end{lstlisting}'); out.append(''); code=False
        i+=1; continue
    if code:
        code_lines.append(line); i+=1; continue
    # Markdown table: header, separator, then consecutive rows.
    if st.startswith('|') and i+1<len(src) and re.match(r'^\s*\|?\s*:?-{3,}',src[i+1]):
        flush_para(); close_list()
        rows=[]
        while i<len(src) and src[i].strip().startswith('|'):
            raw=src[i].strip().strip('|')
            rows.append([x.strip() for x in raw.split('|')]); i+=1
        if len(rows)>1 and all(re.fullmatch(r':?-{3,}:?',x.strip()) for x in rows[1]): rows.pop(1)
        n=max(map(len,rows)); cols=(['p{3.8cm}']+['X']*(n-1)) if n==2 else (['p{0.8cm}','p{3.8cm}','p{1.6cm}','X'] if n==4 else ['>{\\raggedright\\arraybackslash}X']*n); out.append(r'\small\begin{tabularx}{\linewidth}{'+'|'+('|'.join(cols))+'|}')
        out.append(r'\hline')
        for ri,row in enumerate(rows):
            row=row+['']*(n-len(row))
            out.append(' & '.join(inline(c) for c in row)+r' \\ \hline')
        out.append(r'\end{tabularx}\normalsize'); out.append(''); continue
    if not st or st=='---': flush_para(); close_list(); i+=1; continue
    m=re.match(r'^(#{1,6})\s+(.*)',st)
    if m:
        flush_para(); close_list(); title=m.group(2)
        title=re.sub(r'^\d+(?:\.\d+)*\.\s*','',title)
        command={2:'section',3:'subsection',4:'subsubsection'}.get(len(m.group(1)),'paragraph')
        if title=='Список использованных источников': out.append(r'\clearpage')
        out.append('\\'+command+'{'+inline(title)+'}')
        out.append(''); i+=1; continue
    m=re.match(r'^[-*]\s+(.*)',st)
    if m:
        flush_para()
        if list_kind!='itemize': close_list(); out.append(r'\begin{itemize}'); list_kind='itemize'
        out.append(r'\item '+inline(m.group(1))); i+=1; continue
    m=re.match(r'^\d+\.\s+(.*)',st)
    if m:
        flush_para()
        if list_kind!='enumerate': close_list(); out.append(r'\begin{enumerate}'); list_kind='enumerate'
        out.append(r'\item '+inline(m.group(1))); i+=1; continue
    flush_para(); close_list(); para=[st]; i+=1
flush_para(); close_list()
out.append(r'\end{document}')
(root/'reports/lab1/report.tex').write_text(head+'\n'.join(out)+'\n')
