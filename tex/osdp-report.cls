\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{tex/osdp-report}[2025/10/29 Simplified OSDP document class]

\LoadClass[12pt,oneside]{article}

\RequirePackage[margin=1in]{geometry}
\RequirePackage{iftex}
\RequirePackage{xcolor}
\RequirePackage{graphicx}
\RequirePackage{microtype}
\RequirePackage{hyperref}
\RequirePackage{needspace}

\widowpenalty=10000
\clubpenalty=10000
\displaywidowpenalty=10000
\brokenpenalty=10000
\raggedbottom

\ifPDFTeX
  \RequirePackage[T1]{fontenc}
  \RequirePackage{lmodern}
\else
  \RequirePackage{fontspec}
  \defaultfontfeatures{Ligatures=TeX,Scale=MatchLowercase}
  \setmainfont{Carlito-Regular.ttf}[
    Path=fonts/,
    BoldFont=Carlito-Bold.ttf,
    ItalicFont=Carlito-Italic.ttf,
    BoldItalicFont=Carlito-BoldItalic.ttf
  ]
  \setsansfont{Carlito-Regular.ttf}[
    Path=fonts/,
    BoldFont=Carlito-Bold.ttf,
    ItalicFont=Carlito-Italic.ttf,
    BoldItalicFont=Carlito-BoldItalic.ttf
  ]
\fi

\definecolor{OSDPBlue}{HTML}{0B1F4A}
\definecolor{OSDPLightGray}{HTML}{F2F2F2}

\hypersetup{
  colorlinks=true,
  linkcolor=OSDPBlue,
  urlcolor=OSDPBlue,
  citecolor=OSDPBlue,
  linktoc=all,
  pdfauthor={Security Industry Association},
  pdftitle={OSDP Specification}
}
\urlstyle{tt}

\setlength{\parindent}{0pt}
\setlength{\parskip}{0.8em}
\setlength{\emergencystretch}{4em}

\newcommand{\code}[1]{\nolinkurl{#1}}

\renewcommand{\section}{\Needspace{8\baselineskip}\@startsection{section}{1}{0pt}{1.5ex plus .2ex}{0.5ex}{\normalfont\bfseries\Large}}
\renewcommand{\subsection}{\Needspace{6\baselineskip}\@startsection{subsection}{2}{0pt}{1.25ex plus .2ex}{0.4ex}{\normalfont\bfseries\large}}
\renewcommand{\subsubsection}{\Needspace{5\baselineskip}\@startsection{subsubsection}{3}{0pt}{1.1ex plus .2ex}{0.35ex}{\normalfont\bfseries\large}}

\endinput
