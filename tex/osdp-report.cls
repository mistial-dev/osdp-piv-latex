\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{osdp-report}[2025/10/29 Simplified OSDP document class]

\LoadClass[12pt,oneside]{article}

\RequirePackage[margin=1in]{geometry}
\RequirePackage{iftex}
\RequirePackage{xcolor}
\RequirePackage{graphicx}
\RequirePackage{hyperref}

\ifPDFTeX
  \RequirePackage[T1]{fontenc}
  \RequirePackage{lmodern}
\else
  \RequirePackage{fontspec}
  \defaultfontfeatures{Ligatures=TeX,Scale=MatchLowercase}
  \setmainfont{calibri.ttf}[Path=fonts/,BoldFont=calibri-bold.ttf]
  \setsansfont{Arial}
\fi

\definecolor{OSDPBlue}{HTML}{0B1F4A}
\definecolor{OSDPLightGray}{HTML}{F2F2F2}

\hypersetup{
  colorlinks=true,
  linkcolor=OSDPBlue,
  urlcolor=OSDPBlue,
  citecolor=OSDPBlue,
  pdfauthor={Security Industry Association},
  pdftitle={OSDP Specification}
}

\setlength{\parindent}{0pt}
\setlength{\parskip}{0.8em}

\renewcommand{\section}{\@startsection{section}{1}{0pt}{1.5ex plus .2ex}{0.5ex}{\normalfont\bfseries\Large}}
\renewcommand{\subsection}{\@startsection{subsection}{2}{0pt}{1.25ex plus .2ex}{0.4ex}{\normalfont\bfseries\large}}

\endinput
