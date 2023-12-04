---
title: "Markdown Syntax"
date: "1999-05-11"
description: "Markdown Syntax test page"
tags: ["markdown", "css", "html", "themes"]
---

This article offers a sample of basic Markdown syntax that can be used in Hugo content files, also it shows whether basic HTML elements are decorated with CSS in a Hugo theme.

## Headings

The following HTML `<h1>`—`<h6>` elements represent six levels of section headings. `<h1>` is the highest section level while `<h6>` is the lowest.

<!--more-->

# H1

## H2

### H3

#### H4

##### H5

###### H6

## Paragraph

Xerum, quo qui aut unt expliquam qui dolut labo. Aque venitatiusda cum, voluptionse latur sitiae dolessi aut parist aut dollo enim qui voluptate ma dolestendit peritin re plis aut quas inctum laceat est volestemque commosa as cus endigna tectur, offic to cor sequas etum rerum idem sintibus eiur? Quianimin porecus evelectur, cum que nis nust voloribus ratem aut omnimi, sitatur? Quiatem. Nam, omnis sum am facea corem alique molestrunt et eos evelece arcillit ut aut eos eos nus, sin conecerem erum fuga. Ri oditatquam, ad quibus unda veliamenimin cusam et facea ipsamus es exerum sitate dolores editium rerore eost, temped molorro ratiae volorro te reribus dolorer sperchicium faceata tiustia prat.

Itatur? Quiatae cullecum rem ent aut odis in re eossequodi nonsequ idebis ne sapicia is sinveli squiatum, core et que aut hariosam ex eat.

## Blockquotes

The blockquote element represents content that is quoted from another source, optionally with a citation which must be within a `footer` or `cite` element, and optionally with in-line changes such as annotations and abbreviations.

#### Blockquote without attribution

> Tiam, ad mint andaepu dandae nostion secatur sequo quae.
> **Note** that you can use _Markdown syntax_ within a blockquote.

#### Blockquote with attribution

> Don't communicate by sharing memory, share memory by communicating.</p>
> — <cite>Rob Pike[^1]</cite>

[^1]: The above quote is excerpted from Rob Pike's [talk](https://www.youtube.com/watch?v=PAAkCSZUG1c) during Gopherfest, November 18, 2015.

## Tables

Tables aren't part of the core Markdown spec, but Hugo supports supports them out-of-the-box.

| Name  | Age |
| ----- | --- |
| Bob   | 27  |
| Alice | 23  |

#### Inline Markdown within tables

| Inline&nbsp;&nbsp;&nbsp; | Markdown&nbsp;&nbsp;&nbsp; | In&nbsp;&nbsp;&nbsp;                | Table  |
| ------------------------ | -------------------------- | ----------------------------------- | ------ |
| _italics_                | **bold**                   | ~~strikethrough~~&nbsp;&nbsp;&nbsp; | `code` |

## Code Blocks

#### Code block with backticks

```html
html
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8" />
        <title>Example HTML5 Document</title>
    </head>
    <body>
        <p>Test</p>
    </body>
</html>
```

#### Code block indented with four spaces

    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Example HTML5 Document</title>
    </head>
    <body>
        <p>Test</p>
    </body>
    </html>

## List Types

#### Ordered List

1. First item
2. Second item
3. Third item

#### Unordered List

-   List item
-   Another item
-   And another item

#### Nested list

-   Item

1. First Sub-item
2. Second Sub-item

## Other Elements — abbr, sub, sup, kbd, mark

<abbr title="Graphics Interchange Format">GIF</abbr> is a bitmap image format.

H<sub>2</sub>O

X<sup>n</sup> + Y<sup>n</sup> = Z<sup>n</sup>

Press <kbd><kbd>CTRL</kbd>+<kbd>ALT</kbd>+<kbd>Delete</kbd></kbd> to end the session.

Most <mark>salamanders</mark> are nocturnal, and hunt for insects, worms, and other small creatures.

## Comments

[comment]: # (This actually is the most platform independent comment. Add an empty line before)



## Latex support

| To get | Use | 
| ------------------------ | -------------------------- | 
| \\(a^2 + b^2 = c^2\\)  | `\\(a^2 + b^2 = c^2\\)`          | 
| \\({(a+b)}^2 = a^2 + 2ab + b^2\\)  | `\\({(a+b)}^2 = a^2 + 2ab + b^2\\)`          | 
| \\( {(a+b)} \mod n = a \mod n + b \mod n \\)|`\\( {(a+b)} \mod n = a \mod n + b \mod n \\)`|
| \\( n \equiv 0 \pmod n \\)|`\\( n \equiv 0 \pmod n  \\)`|
| \\( \frac {a}{b} ~\quad {a}/{b^3}  \space \quad \dfrac{a}{b}\\)|`\\( \frac {a}{b} ~\quad {a}/{b^3}  \space \quad \dfrac{a}{b}\\)`|
| \\( \fcolorbox{red}{aqua}{$F=ma$} \\)|`\\( \fcolorbox{red}{aqua}{$F=ma$} \\)`|
| \\( \Z \R \N \Reals \Complex \\)|`\\( \Z \R \N \Reals \Complex \\)`|
|$$ \Z \R \N \Reals \Complex $$ | `$$ \Z \R \N \Reals \Complex $$`|
|\\( \text{This is a sentence with under\\_score}\\)|`\\( \text{This is a sentence with under\\_score}\\)`|
|$$ \tag{mod N} x+y^{2x} $$ |`$$ \tag{mod N} x+y^{2x} $$`|
|\\( \stackrel {?}{=} \overset {!}{=} \underset {\\$}{=} \\)|`\\( \stackrel {?}{=} \overset {!}{=} \underset {\\$}{=} \\)`|
| \\( \forall \therefore \because \in \notin \subset \supset \exist \\)|`\\( \forall \therefore \because \in \notin \subset \supset \exist \\)`|
|\\(A\oplus B = P \bigoplus Q\\)|`\\(A\oplus B = P \bigoplus Q\\)`|
|\\(\tiny Aa \scriptsize Aa \footnotesize Aa \small Aa \normalsize Aa \\)|`\\(\tiny Aa \scriptsize Aa \footnotesize Aa \small Aa \normalsize Aa \\)`|
|\\(\large Aa \Large Aa \LARGE Aa \huge Aa \Huge Aa \normalsize \\)|`\\(\large Aa \Large Aa \LARGE Aa \huge Aa \Huge Aa \normalsize \\)`|
|$$<br>\Z<br>\R$$||
|∀∴∁∵∃∣∈∈/∋⊂⊃∧∨↦→←↔¬ ℂ ℍ ℕ ℙ ℚ ℝ|∀∴∁∵∃∣∈∈/∋⊂⊃∧∨↦→←↔¬ ℂ ℍ ℕ ℙ ℚ ℝ|
