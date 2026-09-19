<?php

declare(strict_types=1);

use PhpCsFixer\Config;
use PhpCsFixer\Finder;

$finder = Finder::create()
    ->in(__DIR__)
    ->name('*.php')
    ->name('*.phtml')
    ->exclude(['vendor', 'node_modules'])
    ->append([__FILE__]);

return (new Config())
    ->setRiskyAllowed(false)
    ->setUsingCache(false)
    ->setRules([
        '@PER-CS3x0'             => true,
        'array_syntax'           => ['syntax' => 'short'],
        'binary_operator_spaces' => [
            'default'   => 'single_space',
            'operators' => ['=' => 'align_single_space_minimal', '=>' => 'align_single_space_minimal'],
        ],
        'blank_line_before_statement'     => ['statements' => ['return', 'try']],
        'cast_spaces'                     => ['space' => 'single'],
        'concat_space'                    => ['spacing' => 'one'],
        'fully_qualified_strict_types'    => ['import_symbols' => true],
        'global_namespace_import'         => ['import_classes' => true],
        'heredoc_indentation'             => ['indentation' => 'same_as_start'],
        'method_chaining_indentation'     => true,
        'no_multiple_statements_per_line' => true,
        'no_unused_imports'               => true,
        'ordered_imports'                 => ['sort_algorithm' => 'alpha', 'imports_order' => ['class', 'function', 'const']],
        'single_import_per_statement'     => true,
        'single_line_empty_body'          => false,
        'class_attributes_separation'     => ['elements' => ['method' => 'one']],
        'whitespace_after_comma_in_array' => true,
    ])
    ->setFinder($finder);
