<?php
/**
 * SecurityFilters
 *
 * Collection of security filters for content sanitization
 */
class SecurityFilters {
    /**
     * Main filter method - applies all content filters
     *
     * @param string $content Content to filter
     * @return string Filtered content
     */
    public static function filterContent($content) {
        $codeBlocks = [];

        // Protect fenced code blocks (``` ... ```)
        $content = preg_replace_callback('/```[\s\S]*?```/', function($m) use (&$codeBlocks) {
            $placeholder = "\x00CODE" . count($codeBlocks) . "\x00";
            $codeBlocks[$placeholder] = $m[0];
            return $placeholder;
        }, $content);

        // Protect inline code (` ... `)
        $content = preg_replace_callback('/`[^`\n]+`/', function($m) use (&$codeBlocks) {
            $placeholder = "\x00CODE" . count($codeBlocks) . "\x00";
            $codeBlocks[$placeholder] = $m[0];
            return $placeholder;
        }, $content);

        // Apply KaTeX filter only to content outside code blocks
        $content = self::filterKaTeX($content);

        // Restore original code blocks
        foreach ($codeBlocks as $placeholder => $original) {
            $content = str_replace($placeholder, $original, $content);
        }

        return $content;
    }

    /**
     * KaTeX Filter
     */
    private static function filterKaTeX($content) {
        $blacklistedCommands = [
            '\html',
            '\htmlStyle',
            '\href',
            '\def',
            '\newcommand',
            '\renewcommand',
            '\mathml',
            '\style'
        ];

        $blacklistedTags = [
            '<script',
            '<img',
            '<iframe',
            '<object',
            '<embed',
            '<math',
            '<svg',
            'javascript:',
            'data:',
            'vbscript:'
        ];

        // extract and filter all katex blocks
        $pattern = '/\$\$(.*?)\$\$|\$(.*?)\$/s';
        return preg_replace_callback($pattern, function($matches) use ($blacklistedCommands, $blacklistedTags) {
            $math = !empty($matches[1]) ? $matches[1] : $matches[2];
            $isDisplay = !empty($matches[1]);
            // remove blacklisted commands
            foreach ($blacklistedCommands as $command) {
                $math = str_replace($command, '\\text{BLOCKED}', $math);
            }
            // remove malicious tags
            foreach ($blacklistedTags as $tag) {
                $math = str_ireplace($tag, '&lt;blocked&gt;', $math);
            }
            // prevent math mode escaping
            $math = preg_replace('/\\\\(?![\w\s{},\\\\_^])/u', '\\\\textbackslash', $math);
            // return with appropriate delimiters
            return $isDisplay ? "$$" . $math . "$$" : "$" . $math . "$";
        }, $content);
    }
}
