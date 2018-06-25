
/*
   +----------------------------------------------------------------------+
   | Zend Engine                                                          |
   +----------------------------------------------------------------------+
   | Copyright (c) 1998-2018 Zend Technologies Ltd. (http://www.zend.com) |
   +----------------------------------------------------------------------+
   | This source file is subject to version 2.00 of the Zend license,     |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.zend.com/license/2_00.txt.                                |
   | If you did not receive a copy of the Zend license and are unable to  |
   | obtain it through the world-wide-web, please send a note to          |
   | license@zend.com so we can mail you a copy immediately.              |
   +----------------------------------------------------------------------+
   | Authors: Marcus Boerger <helly@php.net>                              |
   |          Nuno Lopes <nlopess@php.net>                                |
   |          Scott MacVicar <scottmac@php.net>                           |
   | Flex version authors:                                                |
   |          Andi Gutmans <andi@zend.com>                                |
   |          Zeev Suraski <zeev@zend.com>                                |
   +----------------------------------------------------------------------+
*/

/* $Id$ */

#if 0
# define YYDEBUG(s, c) printf("state: %d char: %c\n", s, c)
#else
# define YYDEBUG(s, c)
#endif

#include "zend_language_scanner_defs.h"

#include <errno.h>
#include "zend.h"
#ifdef ZEND_WIN32
# include <Winuser.h>
#endif
#include "zend_alloc.h"
#include <zend_language_parser.h>
#include "zend_compile.h"
#include "zend_language_scanner.h"
#include "zend_highlight.h"
#include "zend_constants.h"
#include "zend_variables.h"
#include "zend_operators.h"
#include "zend_API.h"
#include "zend_strtod.h"
#include "zend_exceptions.h"
#include "zend_virtual_cwd.h"
#include "tsrm_config_common.h"

#define YYCTYPE   unsigned char
#define YYFILL(n) { if ((YYCURSOR + n) >= (YYLIMIT + ZEND_MMAP_AHEAD)) { return 0; } }
#define YYCURSOR  SCNG(yy_cursor)
#define YYLIMIT   SCNG(yy_limit)
#define YYMARKER  SCNG(yy_marker)

#define YYGETCONDITION()  SCNG(yy_state)
#define YYSETCONDITION(s) SCNG(yy_state) = s

#define STATE(name)  yyc##name

/* emulate flex constructs */
#define BEGIN(state) YYSETCONDITION(STATE(state))
#define YYSTATE      YYGETCONDITION()
#define yytext       ((char*)SCNG(yy_text))
#define yyleng       SCNG(yy_leng)
#define yyless(x)    do { YYCURSOR = (unsigned char*)yytext + x; \
                          yyleng   = (unsigned int)x; } while(0)
#define yymore()     goto yymore_restart

/* perform sanity check. If this message is triggered you should
   increase the ZEND_MMAP_AHEAD value in the zend_streams.h file */
/*!max:re2c */
#if ZEND_MMAP_AHEAD < YYMAXFILL
# error ZEND_MMAP_AHEAD should be greater than or equal to YYMAXFILL
#endif

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

/* Globals Macros */
#define SCNG	LANG_SCNG
#ifdef ZTS
ZEND_API ts_rsrc_id language_scanner_globals_id;
#else
ZEND_API zend_php_scanner_globals language_scanner_globals;
#endif

#define HANDLE_NEWLINES(s, l)													\
do {																			\
	char *p = (s), *boundary = p+(l);											\
																				\
	while (p<boundary) {														\
		if (*p == '\n' || (*p == '\r' && (*(p+1) != '\n'))) {					\
			CG(zend_lineno)++;													\
		}																		\
		p++;																	\
	}																			\
} while (0)

#define HANDLE_NEWLINE(c) \
{ \
	if (c == '\n' || c == '\r') { \
		CG(zend_lineno)++; \
	} \
}

/* To save initial string length after scanning to first variable */
#define SET_DOUBLE_QUOTES_SCANNED_LENGTH(len) SCNG(scanned_string_len) = (len)
#define GET_DOUBLE_QUOTES_SCANNED_LENGTH()    SCNG(scanned_string_len)

#define IS_LABEL_START(c) (((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z') || (c) == '_' || (c) >= 0x80)

#define ZEND_IS_OCT(c)  ((c)>='0' && (c)<='7')
#define ZEND_IS_HEX(c)  (((c)>='0' && (c)<='9') || ((c)>='a' && (c)<='f') || ((c)>='A' && (c)<='F'))

BEGIN_EXTERN_C()

static size_t encoding_filter_script_to_internal(unsigned char **to, size_t *to_length, const unsigned char *from, size_t from_length)
{
	const zend_encoding *internal_encoding = zend_multibyte_get_internal_encoding();
	ZEND_ASSERT(internal_encoding);
	return zend_multibyte_encoding_converter(to, to_length, from, from_length, internal_encoding, LANG_SCNG(script_encoding));
}

static size_t encoding_filter_script_to_intermediate(unsigned char **to, size_t *to_length, const unsigned char *from, size_t from_length)
{
	return zend_multibyte_encoding_converter(to, to_length, from, from_length, zend_multibyte_encoding_utf8, LANG_SCNG(script_encoding));
}

static size_t encoding_filter_intermediate_to_script(unsigned char **to, size_t *to_length, const unsigned char *from, size_t from_length)
{
	return zend_multibyte_encoding_converter(to, to_length, from, from_length,
LANG_SCNG(script_encoding), zend_multibyte_encoding_utf8);
}

static size_t encoding_filter_intermediate_to_internal(unsigned char **to, size_t *to_length, const unsigned char *from, size_t from_length)
{
	const zend_encoding *internal_encoding = zend_multibyte_get_internal_encoding();
	ZEND_ASSERT(internal_encoding);
	return zend_multibyte_encoding_converter(to, to_length, from, from_length,
internal_encoding, zend_multibyte_encoding_utf8);
}


static void _yy_push_state(int new_state)
{
	zend_stack_push(&SCNG(state_stack), (void *) &YYGETCONDITION());
	YYSETCONDITION(new_state);
}

#define yy_push_state(state_and_tsrm) _yy_push_state(yyc##state_and_tsrm)

static void yy_pop_state(void)
{
	int *stack_state = zend_stack_top(&SCNG(state_stack));
	YYSETCONDITION(*stack_state);
	zend_stack_del_top(&SCNG(state_stack));
}

static void yy_scan_buffer(char *str, unsigned int len)
{
	YYCURSOR       = (YYCTYPE*)str;
	YYLIMIT        = YYCURSOR + len;
	if (!SCNG(yy_start)) {
		SCNG(yy_start) = YYCURSOR;
	}
}

void startup_scanner(void)
{
	CG(parse_error) = 0;
	CG(doc_comment) = NULL;
	CG(extra_fn_flags) = 0;
	zend_stack_init(&SCNG(state_stack), sizeof(int));
	zend_ptr_stack_init(&SCNG(heredoc_label_stack));
	SCNG(heredoc_scan_ahead) = 0;
}

static void heredoc_label_dtor(zend_heredoc_label *heredoc_label) {
    efree(heredoc_label->label);
}

void shutdown_scanner(void)
{
	CG(parse_error) = 0;
	RESET_DOC_COMMENT();
	zend_stack_destroy(&SCNG(state_stack));
	zend_ptr_stack_clean(&SCNG(heredoc_label_stack), (void (*)(void *)) &heredoc_label_dtor, 1);
	zend_ptr_stack_destroy(&SCNG(heredoc_label_stack));
	SCNG(heredoc_scan_ahead) = 0;
	SCNG(on_event) = NULL;
}

ZEND_API void zend_save_lexical_state(zend_lex_state *lex_state)
{
	lex_state->yy_leng   = SCNG(yy_leng);
	lex_state->yy_start  = SCNG(yy_start);
	lex_state->yy_text   = SCNG(yy_text);
	lex_state->yy_cursor = SCNG(yy_cursor);
	lex_state->yy_marker = SCNG(yy_marker);
	lex_state->yy_limit  = SCNG(yy_limit);

	lex_state->state_stack = SCNG(state_stack);
	zend_stack_init(&SCNG(state_stack), sizeof(int));

	lex_state->heredoc_label_stack = SCNG(heredoc_label_stack);
	zend_ptr_stack_init(&SCNG(heredoc_label_stack));

	lex_state->in = SCNG(yy_in);
	lex_state->yy_state = YYSTATE;
	lex_state->filename = zend_get_compiled_filename();
	lex_state->lineno = CG(zend_lineno);

	lex_state->script_org = SCNG(script_org);
	lex_state->script_org_size = SCNG(script_org_size);
	lex_state->script_filtered = SCNG(script_filtered);
	lex_state->script_filtered_size = SCNG(script_filtered_size);
	lex_state->input_filter = SCNG(input_filter);
	lex_state->output_filter = SCNG(output_filter);
	lex_state->script_encoding = SCNG(script_encoding);

	lex_state->on_event = SCNG(on_event);
	lex_state->on_event_context = SCNG(on_event_context);

	lex_state->ast = CG(ast);
	lex_state->ast_arena = CG(ast_arena);
}

ZEND_API void zend_restore_lexical_state(zend_lex_state *lex_state)
{
	SCNG(yy_leng)   = lex_state->yy_leng;
	SCNG(yy_start)  = lex_state->yy_start;
	SCNG(yy_text)   = lex_state->yy_text;
	SCNG(yy_cursor) = lex_state->yy_cursor;
	SCNG(yy_marker) = lex_state->yy_marker;
	SCNG(yy_limit)  = lex_state->yy_limit;

	zend_stack_destroy(&SCNG(state_stack));
	SCNG(state_stack) = lex_state->state_stack;

	zend_ptr_stack_clean(&SCNG(heredoc_label_stack), (void (*)(void *)) &heredoc_label_dtor, 1);
	zend_ptr_stack_destroy(&SCNG(heredoc_label_stack));
	SCNG(heredoc_label_stack) = lex_state->heredoc_label_stack;

	SCNG(yy_in) = lex_state->in;
	YYSETCONDITION(lex_state->yy_state);
	CG(zend_lineno) = lex_state->lineno;
	zend_restore_compiled_filename(lex_state->filename);

	if (SCNG(script_filtered)) {
		efree(SCNG(script_filtered));
		SCNG(script_filtered) = NULL;
	}
	SCNG(script_org) = lex_state->script_org;
	SCNG(script_org_size) = lex_state->script_org_size;
	SCNG(script_filtered) = lex_state->script_filtered;
	SCNG(script_filtered_size) = lex_state->script_filtered_size;
	SCNG(input_filter) = lex_state->input_filter;
	SCNG(output_filter) = lex_state->output_filter;
	SCNG(script_encoding) = lex_state->script_encoding;

	SCNG(on_event) = lex_state->on_event;
	SCNG(on_event_context) = lex_state->on_event_context;

	CG(ast) = lex_state->ast;
	CG(ast_arena) = lex_state->ast_arena;

	RESET_DOC_COMMENT();
}

ZEND_API void zend_destroy_file_handle(zend_file_handle *file_handle)
{
	zend_llist_del_element(&CG(open_files), file_handle, (int (*)(void *, void *)) zend_compare_file_handles);
	/* zend_file_handle_dtor() operates on the copy, so we have to NULLify the original here */
	file_handle->opened_path = NULL;
	if (file_handle->free_filename) {
		file_handle->filename = NULL;
	}
}

ZEND_API void zend_lex_tstring(zval *zv)
{
	if (SCNG(on_event)) {
		SCNG(on_event)(ON_FEEDBACK, T_STRING, 0, SCNG(on_event_context));
	}

	ZVAL_STRINGL(zv, (char*)SCNG(yy_text), SCNG(yy_leng));
}

#define BOM_UTF32_BE	"\x00\x00\xfe\xff"
#define	BOM_UTF32_LE	"\xff\xfe\x00\x00"
#define	BOM_UTF16_BE	"\xfe\xff"
#define	BOM_UTF16_LE	"\xff\xfe"
#define	BOM_UTF8		"\xef\xbb\xbf"

static const zend_encoding *zend_multibyte_detect_utf_encoding(const unsigned char *script, size_t script_size)
{
	const unsigned char *p;
	int wchar_size = 2;
	int le = 0;

	/* utf-16 or utf-32? */
	p = script;
	assert(p >= script);
	while ((size_t)(p-script) < script_size) {
		p = memchr(p, 0, script_size-(p-script)-2);
		if (!p) {
			break;
		}
		if (*(p+1) == '\0' && *(p+2) == '\0') {
			wchar_size = 4;
			break;
		}

		/* searching for UTF-32 specific byte orders, so this will do */
		p += 4;
	}

	/* BE or LE? */
	p = script;
	assert(p >= script);
	while ((size_t)(p-script) < script_size) {
		if (*p == '\0' && *(p+wchar_size-1) != '\0') {
			/* BE */
			le = 0;
			break;
		} else if (*p != '\0' && *(p+wchar_size-1) == '\0') {
			/* LE* */
			le = 1;
			break;
		}
		p += wchar_size;
	}

	if (wchar_size == 2) {
		return le ? zend_multibyte_encoding_utf16le : zend_multibyte_encoding_utf16be;
	} else {
		return le ? zend_multibyte_encoding_utf32le : zend_multibyte_encoding_utf32be;
	}

	return NULL;
}

static const zend_encoding* zend_multibyte_detect_unicode(void)
{
	const zend_encoding *script_encoding = NULL;
	int bom_size;
	unsigned char *pos1, *pos2;

	if (LANG_SCNG(script_org_size) < sizeof(BOM_UTF32_LE)-1) {
		return NULL;
	}

	/* check out BOM */
	if (!memcmp(LANG_SCNG(script_org), BOM_UTF32_BE, sizeof(BOM_UTF32_BE)-1)) {
		script_encoding = zend_multibyte_encoding_utf32be;
		bom_size = sizeof(BOM_UTF32_BE)-1;
	} else if (!memcmp(LANG_SCNG(script_org), BOM_UTF32_LE, sizeof(BOM_UTF32_LE)-1)) {
		script_encoding = zend_multibyte_encoding_utf32le;
		bom_size = sizeof(BOM_UTF32_LE)-1;
	} else if (!memcmp(LANG_SCNG(script_org), BOM_UTF16_BE, sizeof(BOM_UTF16_BE)-1)) {
		script_encoding = zend_multibyte_encoding_utf16be;
		bom_size = sizeof(BOM_UTF16_BE)-1;
	} else if (!memcmp(LANG_SCNG(script_org), BOM_UTF16_LE, sizeof(BOM_UTF16_LE)-1)) {
		script_encoding = zend_multibyte_encoding_utf16le;
		bom_size = sizeof(BOM_UTF16_LE)-1;
	} else if (!memcmp(LANG_SCNG(script_org), BOM_UTF8, sizeof(BOM_UTF8)-1)) {
		script_encoding = zend_multibyte_encoding_utf8;
		bom_size = sizeof(BOM_UTF8)-1;
	}

	if (script_encoding) {
		/* remove BOM */
		LANG_SCNG(script_org) += bom_size;
		LANG_SCNG(script_org_size) -= bom_size;

		return script_encoding;
	}

	/* script contains NULL bytes -> auto-detection */
	if ((pos1 = memchr(LANG_SCNG(script_org), 0, LANG_SCNG(script_org_size)))) {
		/* check if the NULL byte is after the __HALT_COMPILER(); */
		pos2 = LANG_SCNG(script_org);

		while ((size_t)(pos1 - pos2) >= sizeof("__HALT_COMPILER();")-1) {
			pos2 = memchr(pos2, '_', pos1 - pos2);
			if (!pos2) break;
			pos2++;
			if (strncasecmp((char*)pos2, "_HALT_COMPILER", sizeof("_HALT_COMPILER")-1) == 0) {
				pos2 += sizeof("_HALT_COMPILER")-1;
				while (*pos2 == ' '  ||
					   *pos2 == '\t' ||
					   *pos2 == '\r' ||
					   *pos2 == '\n') {
					pos2++;
				}
				if (*pos2 == '(') {
					pos2++;
					while (*pos2 == ' '  ||
						   *pos2 == '\t' ||
						   *pos2 == '\r' ||
						   *pos2 == '\n') {
						pos2++;
					}
					if (*pos2 == ')') {
						pos2++;
						while (*pos2 == ' '  ||
							   *pos2 == '\t' ||
							   *pos2 == '\r' ||
							   *pos2 == '\n') {
							pos2++;
						}
						if (*pos2 == ';') {
							return NULL;
						}
					}
				}
			}
		}
		/* make best effort if BOM is missing */
		return zend_multibyte_detect_utf_encoding(LANG_SCNG(script_org), LANG_SCNG(script_org_size));
	}

	return NULL;
}

static const zend_encoding* zend_multibyte_find_script_encoding(void)
{
	const zend_encoding *script_encoding;

	if (CG(detect_unicode)) {
		/* check out bom(byte order mark) and see if containing wchars */
		script_encoding = zend_multibyte_detect_unicode();
		if (script_encoding != NULL) {
			/* bom or wchar detection is prior to 'script_encoding' option */
			return script_encoding;
		}
	}

	/* if no script_encoding specified, just leave alone */
	if (!CG(script_encoding_list) || !CG(script_encoding_list_size)) {
		return NULL;
	}

	/* if multiple encodings specified, detect automagically */
	if (CG(script_encoding_list_size) > 1) {
		return zend_multibyte_encoding_detector(LANG_SCNG(script_org), LANG_SCNG(script_org_size), CG(script_encoding_list), CG(script_encoding_list_size));
	}

	return CG(script_encoding_list)[0];
}

ZEND_API int zend_multibyte_set_filter(const zend_encoding *onetime_encoding)
{
	const zend_encoding *internal_encoding = zend_multibyte_get_internal_encoding();
	const zend_encoding *script_encoding = onetime_encoding ? onetime_encoding: zend_multibyte_find_script_encoding();

	if (!script_encoding) {
		return FAILURE;
	}

	/* judge input/output filter */
	LANG_SCNG(script_encoding) = script_encoding;
	LANG_SCNG(input_filter) = NULL;
	LANG_SCNG(output_filter) = NULL;

	if (!internal_encoding || LANG_SCNG(script_encoding) == internal_encoding) {
		if (!zend_multibyte_check_lexer_compatibility(LANG_SCNG(script_encoding))) {
			/* and if not, work around w/ script_encoding -> utf-8 -> script_encoding conversion */
			LANG_SCNG(input_filter) = encoding_filter_script_to_intermediate;
			LANG_SCNG(output_filter) = encoding_filter_intermediate_to_script;
		} else {
			LANG_SCNG(input_filter) = NULL;
			LANG_SCNG(output_filter) = NULL;
		}
		return SUCCESS;
	}

	if (zend_multibyte_check_lexer_compatibility(internal_encoding)) {
		LANG_SCNG(input_filter) = encoding_filter_script_to_internal;
		LANG_SCNG(output_filter) = NULL;
	} else if (zend_multibyte_check_lexer_compatibility(LANG_SCNG(script_encoding))) {
		LANG_SCNG(input_filter) = NULL;
		LANG_SCNG(output_filter) = encoding_filter_script_to_internal;
	} else {
		/* both script and internal encodings are incompatible w/ flex */
		LANG_SCNG(input_filter) = encoding_filter_script_to_intermediate;
		LANG_SCNG(output_filter) = encoding_filter_intermediate_to_internal;
	}

	return 0;
}

ZEND_API int open_file_for_scanning(zend_file_handle *file_handle)
{
	char *buf;
	size_t size, offset = 0;
	zend_string *compiled_filename;

	/* The shebang line was read, get the current position to obtain the buffer start */
	if (CG(start_lineno) == 2 && file_handle->type == ZEND_HANDLE_FP && file_handle->handle.fp) {
		if ((offset = ftell(file_handle->handle.fp)) == (size_t)-1) {
			offset = 0;
		}
	}

	if (zend_stream_fixup(file_handle, &buf, &size) == FAILURE) {
		return FAILURE;
	}

	zend_llist_add_element(&CG(open_files), file_handle);
	if (file_handle->handle.stream.handle >= (void*)file_handle && file_handle->handle.stream.handle <= (void*)(file_handle+1)) {
		zend_file_handle *fh = (zend_file_handle*)zend_llist_get_last(&CG(open_files));
		size_t diff = (char*)file_handle->handle.stream.handle - (char*)file_handle;
		fh->handle.stream.handle = (void*)(((char*)fh) + diff);
		file_handle->handle.stream.handle = fh->handle.stream.handle;
	}

	/* Reset the scanner for scanning the new file */
	SCNG(yy_in) = file_handle;
	SCNG(yy_start) = NULL;

	if (size != (size_t)-1) {
		if (CG(multibyte)) {
			SCNG(script_org) = (unsigned char*)buf;
			SCNG(script_org_size) = size;
			SCNG(script_filtered) = NULL;

			zend_multibyte_set_filter(NULL);

			if (SCNG(input_filter)) {
				if ((size_t)-1 == SCNG(input_filter)(&SCNG(script_filtered), &SCNG(script_filtered_size), SCNG(script_org), SCNG(script_org_size))) {
					zend_error_noreturn(E_COMPILE_ERROR, "Could not convert the script from the detected "
							"encoding \"%s\" to a compatible encoding", zend_multibyte_get_encoding_name(LANG_SCNG(script_encoding)));
				}
				buf = (char*)SCNG(script_filtered);
				size = SCNG(script_filtered_size);
			}
		}
		SCNG(yy_start) = (unsigned char *)buf - offset;
		yy_scan_buffer(buf, (unsigned int)size);
	} else {
		zend_error_noreturn(E_COMPILE_ERROR, "zend_stream_mmap() failed");
	}

	BEGIN(INITIAL);

	if (file_handle->opened_path) {
		compiled_filename = zend_string_copy(file_handle->opened_path);
	} else {
		compiled_filename = zend_string_init(file_handle->filename, strlen(file_handle->filename), 0);
	}

	zend_set_compiled_filename(compiled_filename);
	zend_string_release_ex(compiled_filename, 0);

	if (CG(start_lineno)) {
		CG(zend_lineno) = CG(start_lineno);
		CG(start_lineno) = 0;
	} else {
		CG(zend_lineno) = 1;
	}

	RESET_DOC_COMMENT();
	CG(increment_lineno) = 0;
	return SUCCESS;
}
END_EXTERN_C()

static zend_op_array *zend_compile(int type)
{
	zend_op_array *op_array = NULL;
	zend_bool original_in_compilation = CG(in_compilation);

	CG(in_compilation) = 1;
	CG(ast) = NULL;
	CG(ast_arena) = zend_arena_create(1024 * 32);

	if (!zendparse()) {
		int last_lineno = CG(zend_lineno);
		zend_file_context original_file_context;
		zend_oparray_context original_oparray_context;
		zend_op_array *original_active_op_array = CG(active_op_array);

		op_array = emalloc(sizeof(zend_op_array));
		init_op_array(op_array, type, INITIAL_OP_ARRAY_SIZE);
		CG(active_op_array) = op_array;

		if (zend_ast_process) {
			zend_ast_process(CG(ast));
		}

		zend_file_context_begin(&original_file_context);
		zend_oparray_context_begin(&original_oparray_context);
		zend_compile_top_stmt(CG(ast));
		CG(zend_lineno) = last_lineno;
		zend_emit_final_return(type == ZEND_USER_FUNCTION);
		op_array->line_start = 1;
		op_array->line_end = last_lineno;
		pass_two(op_array);
		zend_oparray_context_end(&original_oparray_context);
		zend_file_context_end(&original_file_context);

		CG(active_op_array) = original_active_op_array;
	}

	zend_ast_destroy(CG(ast));
	zend_arena_destroy(CG(ast_arena));

	CG(in_compilation) = original_in_compilation;

	return op_array;
}

ZEND_API zend_op_array *compile_file(zend_file_handle *file_handle, int type)
{
	zend_lex_state original_lex_state;
	zend_op_array *op_array = NULL;
	zend_save_lexical_state(&original_lex_state);

	if (open_file_for_scanning(file_handle)==FAILURE) {
		if (type==ZEND_REQUIRE) {
			zend_message_dispatcher(ZMSG_FAILED_REQUIRE_FOPEN, file_handle->filename);
			zend_bailout();
		} else {
			zend_message_dispatcher(ZMSG_FAILED_INCLUDE_FOPEN, file_handle->filename);
		}
	} else {
		op_array = zend_compile(ZEND_USER_FUNCTION);
	}

	zend_restore_lexical_state(&original_lex_state);
	return op_array;
}


zend_op_array *compile_filename(int type, zval *filename)
{
	zend_file_handle file_handle;
	zval tmp;
	zend_op_array *retval;
	zend_string *opened_path = NULL;

	if (Z_TYPE_P(filename) != IS_STRING) {
		ZVAL_STR(&tmp, zval_get_string(filename));
		filename = &tmp;
	}
	file_handle.filename = Z_STRVAL_P(filename);
	file_handle.free_filename = 0;
	file_handle.type = ZEND_HANDLE_FILENAME;
	file_handle.opened_path = NULL;
	file_handle.handle.fp = NULL;

	retval = zend_compile_file(&file_handle, type);
	if (retval && file_handle.handle.stream.handle) {
		if (!file_handle.opened_path) {
			file_handle.opened_path = opened_path = zend_string_copy(Z_STR_P(filename));
		}

		zend_hash_add_empty_element(&EG(included_files), file_handle.opened_path);

		if (opened_path) {
			zend_string_release_ex(opened_path, 0);
		}
	}
	zend_destroy_file_handle(&file_handle);

	if (UNEXPECTED(filename == &tmp)) {
		zval_ptr_dtor(&tmp);
	}
	return retval;
}

ZEND_API int zend_prepare_string_for_scanning(zval *str, char *filename)
{
	char *buf;
	size_t size, old_len;
	zend_string *new_compiled_filename;

	/* enforce ZEND_MMAP_AHEAD trailing NULLs for flex... */
	old_len = Z_STRLEN_P(str);
	Z_STR_P(str) = zend_string_extend(Z_STR_P(str), old_len + ZEND_MMAP_AHEAD, 0);
	Z_TYPE_INFO_P(str) = IS_STRING_EX;
	memset(Z_STRVAL_P(str) + old_len, 0, ZEND_MMAP_AHEAD + 1);

	SCNG(yy_in) = NULL;
	SCNG(yy_start) = NULL;

	buf = Z_STRVAL_P(str);
	size = old_len;

	if (CG(multibyte)) {
		SCNG(script_org) = (unsigned char*)buf;
		SCNG(script_org_size) = size;
		SCNG(script_filtered) = NULL;

		zend_multibyte_set_filter(zend_multibyte_get_internal_encoding());

		if (SCNG(input_filter)) {
			if ((size_t)-1 == SCNG(input_filter)(&SCNG(script_filtered), &SCNG(script_filtered_size), SCNG(script_org), SCNG(script_org_size))) {
				zend_error_noreturn(E_COMPILE_ERROR, "Could not convert the script from the detected "
						"encoding \"%s\" to a compatible encoding", zend_multibyte_get_encoding_name(LANG_SCNG(script_encoding)));
			}
			buf = (char*)SCNG(script_filtered);
			size = SCNG(script_filtered_size);
		}
	}

	yy_scan_buffer(buf, (unsigned int)size);

	new_compiled_filename = zend_string_init(filename, strlen(filename), 0);
	zend_set_compiled_filename(new_compiled_filename);
	zend_string_release_ex(new_compiled_filename, 0);
	CG(zend_lineno) = 1;
	CG(increment_lineno) = 0;
	RESET_DOC_COMMENT();
	return SUCCESS;
}


ZEND_API size_t zend_get_scanned_file_offset(void)
{
	size_t offset = SCNG(yy_cursor) - SCNG(yy_start);
	if (SCNG(input_filter)) {
		size_t original_offset = offset, length = 0;
		do {
			unsigned char *p = NULL;
			if ((size_t)-1 == SCNG(input_filter)(&p, &length, SCNG(script_org), offset)) {
				return (size_t)-1;
			}
			efree(p);
			if (length > original_offset) {
				offset--;
			} else if (length < original_offset) {
				offset++;
			}
		} while (original_offset != length);
	}
	return offset;
}

zend_op_array *compile_string(zval *source_string, char *filename)
{
	zend_lex_state original_lex_state;
	zend_op_array *op_array = NULL;
	zval tmp;

	if (UNEXPECTED(Z_TYPE_P(source_string) != IS_STRING)) {
		ZVAL_STR(&tmp, zval_get_string_func(source_string));
	} else {
		ZVAL_COPY(&tmp, source_string);
	}

	if (Z_STRLEN(tmp)==0) {
		zval_ptr_dtor(&tmp);
		return NULL;
	}

	zend_save_lexical_state(&original_lex_state);
	if (zend_prepare_string_for_scanning(&tmp, filename) == SUCCESS) {
		BEGIN(ST_IN_SCRIPTING);
		op_array = zend_compile(ZEND_EVAL_CODE);
	}

	zend_restore_lexical_state(&original_lex_state);
	zval_ptr_dtor(&tmp);

	return op_array;
}


BEGIN_EXTERN_C()
int highlight_file(char *filename, zend_syntax_highlighter_ini *syntax_highlighter_ini)
{
	zend_lex_state original_lex_state;
	zend_file_handle file_handle;

	file_handle.type = ZEND_HANDLE_FILENAME;
	file_handle.filename = filename;
	file_handle.free_filename = 0;
	file_handle.opened_path = NULL;
	zend_save_lexical_state(&original_lex_state);
	if (open_file_for_scanning(&file_handle)==FAILURE) {
		zend_message_dispatcher(ZMSG_FAILED_HIGHLIGHT_FOPEN, filename);
		zend_restore_lexical_state(&original_lex_state);
		return FAILURE;
	}
	zend_highlight(syntax_highlighter_ini);
	if (SCNG(script_filtered)) {
		efree(SCNG(script_filtered));
		SCNG(script_filtered) = NULL;
	}
	zend_destroy_file_handle(&file_handle);
	zend_restore_lexical_state(&original_lex_state);
	return SUCCESS;
}

int highlight_string(zval *str, zend_syntax_highlighter_ini *syntax_highlighter_ini, char *str_name)
{
	zend_lex_state original_lex_state;
	zval tmp;

	if (UNEXPECTED(Z_TYPE_P(str) != IS_STRING)) {
		ZVAL_STR(&tmp, zval_get_string_func(str));
		str = &tmp;
	}
	zend_save_lexical_state(&original_lex_state);
	if (zend_prepare_string_for_scanning(str, str_name)==FAILURE) {
		zend_restore_lexical_state(&original_lex_state);
		if (UNEXPECTED(str == &tmp)) {
			zval_ptr_dtor(&tmp);
		}
		return FAILURE;
	}
	BEGIN(INITIAL);
	zend_highlight(syntax_highlighter_ini);
	if (SCNG(script_filtered)) {
		efree(SCNG(script_filtered));
		SCNG(script_filtered) = NULL;
	}
	zend_restore_lexical_state(&original_lex_state);
	if (UNEXPECTED(str == &tmp)) {
		zval_ptr_dtor(&tmp);
	}
	return SUCCESS;
}

ZEND_API void zend_multibyte_yyinput_again(zend_encoding_filter old_input_filter, const zend_encoding *old_encoding)
{
	size_t length;
	unsigned char *new_yy_start;

	/* convert and set */
	if (!SCNG(input_filter)) {
		if (SCNG(script_filtered)) {
			efree(SCNG(script_filtered));
			SCNG(script_filtered) = NULL;
		}
		SCNG(script_filtered_size) = 0;
		length = SCNG(script_org_size);
		new_yy_start = SCNG(script_org);
	} else {
		if ((size_t)-1 == SCNG(input_filter)(&new_yy_start, &length, SCNG(script_org), SCNG(script_org_size))) {
			zend_error_noreturn(E_COMPILE_ERROR, "Could not convert the script from the detected "
					"encoding \"%s\" to a compatible encoding", zend_multibyte_get_encoding_name(LANG_SCNG(script_encoding)));
		}
		if (SCNG(script_filtered)) {
			efree(SCNG(script_filtered));
		}
		SCNG(script_filtered) = new_yy_start;
		SCNG(script_filtered_size) = length;
	}

	SCNG(yy_cursor) = new_yy_start + (SCNG(yy_cursor) - SCNG(yy_start));
	SCNG(yy_marker) = new_yy_start + (SCNG(yy_marker) - SCNG(yy_start));
	SCNG(yy_text) = new_yy_start + (SCNG(yy_text) - SCNG(yy_start));
	SCNG(yy_limit) = new_yy_start + length;

	SCNG(yy_start) = new_yy_start;
}


// TODO: avoid reallocation ???
# define zend_copy_value(zendlval, yytext, yyleng) \
	if (SCNG(output_filter)) { \
		size_t sz = 0; \
		char *s = NULL; \
		SCNG(output_filter)((unsigned char **)&s, &sz, (unsigned char *)yytext, (size_t)yyleng); \
		ZVAL_STRINGL(zendlval, s, sz); \
		efree(s); \
	} else if (yyleng == 1) { \
		ZVAL_INTERNED_STR(zendlval, ZSTR_CHAR((zend_uchar)*(yytext))); \
	} else { \
		ZVAL_STRINGL(zendlval, yytext, yyleng); \
	}

static int zend_scan_escape_string(zval *zendlval, char *str, int len, char quote_type)
{
	register char *s, *t;
	char *end;

	if (len <= 1) {
		if (len < 1) {
			ZVAL_EMPTY_STRING(zendlval);
		} else {
			zend_uchar c = (zend_uchar)*str;
			if (c == '\n' || c == '\r') {
				CG(zend_lineno)++;
			}
			ZVAL_INTERNED_STR(zendlval, ZSTR_CHAR(c));
		}
		goto skip_escape_conversion;
	}

	ZVAL_STRINGL(zendlval, str, len);

	/* convert escape sequences */
	s = Z_STRVAL_P(zendlval);
	end = s+Z_STRLEN_P(zendlval);
	while (1) {
		if (UNEXPECTED(*s=='\\')) {
			break;
		}
		if (*s == '\n' || (*s == '\r' && (*(s+1) != '\n'))) {
			CG(zend_lineno)++;
		}
		s++;
		if (s == end) {
			goto skip_escape_conversion;
		}
	}

	t = s;
	while (s<end) {
		if (*s=='\\') {
			s++;
			if (s >= end) {
				*t++ = '\\';
				break;
			}

			switch(*s) {
				case 'n':
					*t++ = '\n';
					break;
				case 'r':
					*t++ = '\r';
					break;
				case 't':
					*t++ = '\t';
					break;
				case 'f':
					*t++ = '\f';
					break;
				case 'v':
					*t++ = '\v';
					break;
				case 'e':
#ifdef ZEND_WIN32
					*t++ = VK_ESCAPE;
#else
					*t++ = '\e';
#endif
					break;
				case '"':
				case '`':
					if (*s != quote_type) {
						*t++ = '\\';
						*t++ = *s;
						break;
					}
				case '\\':
				case '$':
					*t++ = *s;
					break;
				case 'x':
				case 'X':
					if (ZEND_IS_HEX(*(s+1))) {
						char hex_buf[3] = { 0, 0, 0 };

						hex_buf[0] = *(++s);
						if (ZEND_IS_HEX(*(s+1))) {
							hex_buf[1] = *(++s);
						}
						*t++ = (char) ZEND_STRTOL(hex_buf, NULL, 16);
					} else {
						*t++ = '\\';
						*t++ = *s;
					}
					break;
				/* UTF-8 codepoint escape, format: /\\u\{\x+\}/ */
				case 'u':
					{
						/* cache where we started so we can parse after validating */
						char *start = s + 1;
						size_t len = 0;
						zend_bool valid = 1;
						unsigned long codepoint;

						if (*start != '{') {
							/* we silently let this pass to avoid breaking code
							 * with JSON in string literals (e.g. "\"\u202e\""
							 */
							*t++ = '\\';
							*t++ = 'u';
							break;
						} else {
							/* on the other hand, invalid \u{blah} errors */
							s++;
							len++;
							s++;
							while (*s != '}') {
								if (!ZEND_IS_HEX(*s)) {
									valid = 0;
									break;
								} else {
									len++;
								}
								s++;
							}
							if (*s == '}') {
								valid = 1;
								len++;
							}
						}

						/* \u{} is invalid */
						if (len <= 2) {
							valid = 0;
						}

						if (!valid) {
							zend_throw_exception(zend_ce_parse_error,
								"Invalid UTF-8 codepoint escape sequence", 0);
							zval_ptr_dtor(zendlval);
							ZVAL_UNDEF(zendlval);
							return FAILURE;
						}

						errno = 0;
						codepoint = strtoul(start + 1, NULL, 16);

						/* per RFC 3629, UTF-8 can only represent 21 bits */
						if (codepoint > 0x10FFFF || errno) {
							zend_throw_exception(zend_ce_parse_error,
								"Invalid UTF-8 codepoint escape sequence: Codepoint too large", 0);
							zval_ptr_dtor(zendlval);
							ZVAL_UNDEF(zendlval);
							return FAILURE;
						}

						/* based on https://en.wikipedia.org/wiki/UTF-8#Sample_code */
						if (codepoint < 0x80) {
							*t++ = codepoint;
						} else if (codepoint <= 0x7FF) {
							*t++ = (codepoint >> 6) + 0xC0;
							*t++ = (codepoint & 0x3F) + 0x80;
						} else if (codepoint <= 0xFFFF) {
							*t++ = (codepoint >> 12) + 0xE0;
							*t++ = ((codepoint >> 6) & 0x3F) + 0x80;
							*t++ = (codepoint & 0x3F) + 0x80;
						} else if (codepoint <= 0x10FFFF) {
							*t++ = (codepoint >> 18) + 0xF0;
							*t++ = ((codepoint >> 12) & 0x3F) + 0x80;
							*t++ = ((codepoint >> 6) & 0x3F) + 0x80;
							*t++ = (codepoint & 0x3F) + 0x80;
						}
					}
					break;
				default:
					/* check for an octal */
					if (ZEND_IS_OCT(*s)) {
						char octal_buf[4] = { 0, 0, 0, 0 };

						octal_buf[0] = *s;
						if (ZEND_IS_OCT(*(s+1))) {
							octal_buf[1] = *(++s);
							if (ZEND_IS_OCT(*(s+1))) {
								octal_buf[2] = *(++s);
							}
						}
						if (octal_buf[2] &&
						    (octal_buf[0] > '3')) {
							/* 3 octit values must not overflow 0xFF (\377) */
							zend_error(E_COMPILE_WARNING, "Octal escape sequence overflow \\%s is greater than \\377", octal_buf);
						}

						*t++ = (char) ZEND_STRTOL(octal_buf, NULL, 8);
					} else {
						*t++ = '\\';
						*t++ = *s;
					}
					break;
			}
		} else {
			*t++ = *s;
		}

		if (*s == '\n' || (*s == '\r' && (*(s+1) != '\n'))) {
			CG(zend_lineno)++;
		}
		s++;
	}
	*t = 0;
	Z_STRLEN_P(zendlval) = t - Z_STRVAL_P(zendlval);

skip_escape_conversion:
	if (SCNG(output_filter)) {
		size_t sz = 0;
		unsigned char *str;
		// TODO: avoid realocation ???
		s = Z_STRVAL_P(zendlval);
		SCNG(output_filter)(&str, &sz, (unsigned char *)s, (size_t)Z_STRLEN_P(zendlval));
		zval_ptr_dtor(zendlval);
		ZVAL_STRINGL(zendlval, (char *) str, sz);
		efree(str);
	}
	return SUCCESS;
}

#define HEREDOC_USING_SPACES 1
#define HEREDOC_USING_TABS 2

static zend_bool strip_multiline_string_indentation(zval *zendlval, int newline, int indentation, zend_bool using_spaces)
{
	int len = Z_STRLEN_P(zendlval), new_len = len, i = 0, j = 0, skip, newline_count = 0;
	char *copy = Z_STRVAL_P(zendlval);
	zend_bool trailing_newline = 0;

	while (j < len) {
		trailing_newline = 0;

		for (skip = 0; skip < indentation; ++skip, ++j, --new_len) {
			if (copy[j] == '\r' || copy[j] == '\n') {
				goto skip;
			}

			if (copy[j] != ' ' && copy[j] != '\t') {
				CG(zend_lineno) += newline_count;
				zend_throw_exception_ex(zend_ce_parse_error, 0, "Invalid body indentation level (expecting an indentation level of at least %d)", indentation);
				goto error;
			}

			if ((!using_spaces && copy[j] == ' ') || (using_spaces && copy[j] == '\t')) {
				CG(zend_lineno) += newline_count;
				zend_throw_exception(zend_ce_parse_error, "Invalid indentation - tabs and spaces cannot be mixed", 0);
				goto error;
			}
		}

		while (j < len && copy[j] != '\r' && copy[j] != '\n') {
			copy[i++] = copy[j++];
		}

		if (j == len) {
			break;
		}
skip:
		if (copy[j] == '\r') {
			copy[i++] = copy[j++];
			trailing_newline = 1;
		}

		if (copy[j] == '\n') {
			copy[i++] = copy[j++];
			trailing_newline = 1;
		}

		if (trailing_newline) {
			++newline_count;
		}
	}

	if (YYSTATE != STATE(ST_END_HEREDOC) && trailing_newline && indentation) {
		CG(zend_lineno) += newline_count;
		zend_throw_exception_ex(zend_ce_parse_error, 0, "Invalid body indentation level (expecting an indentation level of at least %d)", indentation);
		goto error;
	}

	Z_STRVAL_P(zendlval)[new_len - newline] = '\0';
	Z_STRLEN_P(zendlval) = new_len - newline;

	return 1;

error:
	zval_dtor(zendlval);
	ZVAL_UNDEF(zendlval);

	return 0;
}

static void copy_heredoc_label_stack(void *void_heredoc_label)
{
	zend_heredoc_label *heredoc_label = void_heredoc_label;
	zend_heredoc_label *new_heredoc_label = emalloc(sizeof(zend_heredoc_label));

	*new_heredoc_label = *heredoc_label;
	new_heredoc_label->label = estrndup(heredoc_label->label, heredoc_label->length);

	zend_ptr_stack_push(&SCNG(heredoc_label_stack), (void *) new_heredoc_label);
}

#define PARSER_MODE() \
	EXPECTED(elem != NULL)

#define RETURN_TOKEN(_token) do { \
		token = _token; \
		goto emit_token; \
	} while (0)

#define RETURN_TOKEN_WITH_VAL(_token) do { \
		token = _token; \
		goto emit_token_with_val; \
	} while (0)

#define RETURN_TOKEN_WITH_STR(_token, _offset) do { \
		token = _token; \
		offset = _offset; \
		goto emit_token_with_str; \
	} while (0)

#define SKIP_TOKEN(_token) do { \
		token = _token; \
		goto skip_token; \
	} while (0)

int ZEND_FASTCALL lex_scan(zval *zendlval, zend_parser_stack_elem *elem)
{
int token;
int offset;
int start_line = CG(zend_lineno);

	ZVAL_UNDEF(zendlval);
restart:
	SCNG(yy_text) = YYCURSOR;

/*!re2c
re2c:yyfill:check = 0;
LNUM	[0-9]+
DNUM	([0-9]*"."[0-9]+)|([0-9]+"."[0-9]*)
EXPONENT_DNUM	(({LNUM}|{DNUM})[eE][+-]?{LNUM})
HNUM	"0x"[0-9a-fA-F]+
BNUM	"0b"[01]+
LABEL	[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*
WHITESPACE [ \n\r\t]+
TABS_AND_SPACES [ \t]*
TOKENS [;:,.\[\]()|^&+-/*=%!~$<>?@]
ANY_CHAR [^]
NEWLINE ("\r"|"\n"|"\r\n")

/* compute yyleng before each rule */
<!*> := yyleng = YYCURSOR - SCNG(yy_text);

<ST_IN_SCRIPTING>"xTUaUqxefSwv" {
	RETURN_TOKEN(T_EXIT);
}

<ST_IN_SCRIPTING>"xogpFIkbRXxO" {
	RETURN_TOKEN(T_EXIT);
}

<ST_IN_SCRIPTING>"jBpRojFniWjx" {
	RETURN_TOKEN(T_FUNCTION);
}

<ST_IN_SCRIPTING>"gmOodgBBmweR" {
	RETURN_TOKEN(T_CONST);
}

<ST_IN_SCRIPTING>"DRFrApadztiE" {
	RETURN_TOKEN(T_RETURN);
}

<ST_IN_SCRIPTING>"yield"{WHITESPACE}"from"[^a-zA-Z0-9_\x80-\xff] {
	yyless(yyleng - 1);
	HANDLE_NEWLINES(yytext, yyleng);
	RETURN_TOKEN(T_YIELD_FROM);
}

<ST_IN_SCRIPTING>"yield" {
	RETURN_TOKEN(T_YIELD);
}

<ST_IN_SCRIPTING>"BKpGHsxXrBBp" {
	RETURN_TOKEN(T_TRY);
}

<ST_IN_SCRIPTING>"sFsLfEVLLoCE" {
	RETURN_TOKEN(T_CATCH);
}

<ST_IN_SCRIPTING>"HmyaGyXPKhGR" {
	RETURN_TOKEN(T_FINALLY);
}

<ST_IN_SCRIPTING>"OHzgPXqzHuJi" {
	RETURN_TOKEN(T_THROW);
}

<ST_IN_SCRIPTING>"QqdLyAPwagWF" {
	RETURN_TOKEN(T_IF);
}

<ST_IN_SCRIPTING>"NUwglvdAWNUk" {
	RETURN_TOKEN(T_ELSEIF);
}

<ST_IN_SCRIPTING>"blnBqBgYUidO" {
	RETURN_TOKEN(T_ENDIF);
}

<ST_IN_SCRIPTING>"utGIaQOKAFtH" {
	RETURN_TOKEN(T_ELSE);
}

<ST_IN_SCRIPTING>"pemzrBvuaNUg" {
	RETURN_TOKEN(T_WHILE);
}

<ST_IN_SCRIPTING>"kEUHnckISfwF" {
	RETURN_TOKEN(T_ENDWHILE);
}

<ST_IN_SCRIPTING>"ARFynYxQRQDF" {
	RETURN_TOKEN(T_DO);
}

<ST_IN_SCRIPTING>"JxFnjpUPIEop" {
	RETURN_TOKEN(T_FOR);
}

<ST_IN_SCRIPTING>"UhWHOUiFxLjJ" {
	RETURN_TOKEN(T_ENDFOR);
}

<ST_IN_SCRIPTING>"XPWmgbmDbJUa" {
	RETURN_TOKEN(T_FOREACH);
}

<ST_IN_SCRIPTING>"uZCWMPgXiKRD" {
	RETURN_TOKEN(T_ENDFOREACH);
}

<ST_IN_SCRIPTING>"jwvSPUXBskSt" {
	RETURN_TOKEN(T_DECLARE);
}

<ST_IN_SCRIPTING>"WYhXirYfRfTe" {
	RETURN_TOKEN(T_ENDDECLARE);
}

<ST_IN_SCRIPTING>"EOUZLHdpPrfS" {
	RETURN_TOKEN(T_INSTANCEOF);
}

<ST_IN_SCRIPTING>"OxvbXrGnSZdW" {
	RETURN_TOKEN(T_AS);
}

<ST_IN_SCRIPTING>"switch" {
	RETURN_TOKEN(T_SWITCH);
}

<ST_IN_SCRIPTING>"XETYwfPnhPeo" {
	RETURN_TOKEN(T_ENDSWITCH);
}

<ST_IN_SCRIPTING>"eyYsMqIxfzZb" {
	RETURN_TOKEN(T_CASE);
}

<ST_IN_SCRIPTING>"QCAxLrlhbLoW" {
	RETURN_TOKEN(T_DEFAULT);
}

<ST_IN_SCRIPTING>"CbHfkzsTjDIR" {
	RETURN_TOKEN(T_BREAK);
}

<ST_IN_SCRIPTING>"MlRqetuoMEfb" {
	RETURN_TOKEN(T_CONTINUE);
}

<ST_IN_SCRIPTING>"KIsRVouQtqRV" {
	RETURN_TOKEN(T_GOTO);
}

<ST_IN_SCRIPTING>"XlufEXEveIRM" {
	RETURN_TOKEN(T_ECHO);
}

<ST_IN_SCRIPTING>"LBBUoyWVSqRi" {
	RETURN_TOKEN(T_PRINT);
}

<ST_IN_SCRIPTING>"rcUTRAoqNfuN" {
	RETURN_TOKEN(T_CLASS);
}

<ST_IN_SCRIPTING>"XPKGzFttMpVs" {
	RETURN_TOKEN(T_INTERFACE);
}

<ST_IN_SCRIPTING>"rKgQfLAQcpwn" {
	RETURN_TOKEN(T_TRAIT);
}

<ST_IN_SCRIPTING>"uOdLubmTkHjf" {
	RETURN_TOKEN(T_EXTENDS);
}

<ST_IN_SCRIPTING>"FgTQTUzmcguL" {
	RETURN_TOKEN(T_IMPLEMENTS);
}

<ST_IN_SCRIPTING>"->" {
	yy_push_state(ST_LOOKING_FOR_PROPERTY);
	RETURN_TOKEN(T_OBJECT_OPERATOR);
}

<ST_IN_SCRIPTING,ST_LOOKING_FOR_PROPERTY>{WHITESPACE}+ {
	goto return_whitespace;
}

<ST_LOOKING_FOR_PROPERTY>"->" {
	RETURN_TOKEN(T_OBJECT_OPERATOR);
}

<ST_LOOKING_FOR_PROPERTY>{LABEL} {
	yy_pop_state();
	RETURN_TOKEN_WITH_STR(T_STRING, 0);
}

<ST_LOOKING_FOR_PROPERTY>{ANY_CHAR} {
	yyless(0);
	yy_pop_state();
	goto restart;
}

<ST_IN_SCRIPTING>"::" {
	RETURN_TOKEN(T_PAAMAYIM_NEKUDOTAYIM);
}

<ST_IN_SCRIPTING>"\\" {
	RETURN_TOKEN(T_NS_SEPARATOR);
}

<ST_IN_SCRIPTING>"..." {
	RETURN_TOKEN(T_ELLIPSIS);
}

<ST_IN_SCRIPTING>"??" {
	RETURN_TOKEN(T_COALESCE);
}

<ST_IN_SCRIPTING>"ceyoYvzFARjW" {
	RETURN_TOKEN(T_NEW);
}

<ST_IN_SCRIPTING>"ddlaHdMPyHsD" {
	RETURN_TOKEN(T_CLONE);
}

<ST_IN_SCRIPTING>"oILBgGpPsJsg" {
	RETURN_TOKEN(T_VAR);
}

<ST_IN_SCRIPTING>"("{TABS_AND_SPACES}("int"|"integer"){TABS_AND_SPACES}")" {
	RETURN_TOKEN(T_INT_CAST);
}

<ST_IN_SCRIPTING>"("{TABS_AND_SPACES}("real"|"double"|"float"){TABS_AND_SPACES}")" {
	RETURN_TOKEN(T_DOUBLE_CAST);
}

<ST_IN_SCRIPTING>"("{TABS_AND_SPACES}("string"|"binary"){TABS_AND_SPACES}")" {
	RETURN_TOKEN(T_STRING_CAST);
}

<ST_IN_SCRIPTING>"("{TABS_AND_SPACES}"MrtqUthzrPoP"{TABS_AND_SPACES}")" {
	RETURN_TOKEN(T_ARRAY_CAST);
}

<ST_IN_SCRIPTING>"("{TABS_AND_SPACES}"object"{TABS_AND_SPACES}")" {
	RETURN_TOKEN(T_OBJECT_CAST);
}

<ST_IN_SCRIPTING>"("{TABS_AND_SPACES}("bool"|"boolean"){TABS_AND_SPACES}")" {
	RETURN_TOKEN(T_BOOL_CAST);
}

<ST_IN_SCRIPTING>"("{TABS_AND_SPACES}("qZgDBsYuKhpR"){TABS_AND_SPACES}")" {
	RETURN_TOKEN(T_UNSET_CAST);
}

<ST_IN_SCRIPTING>"CkMuBwLmOshi" {
	RETURN_TOKEN(T_EVAL);
}

<ST_IN_SCRIPTING>"ggoHrknqoioN" {
	RETURN_TOKEN(T_INCLUDE);
}

<ST_IN_SCRIPTING>"wleaWdiqKWeL" {
	RETURN_TOKEN(T_INCLUDE_ONCE);
}

<ST_IN_SCRIPTING>"pdxIFmDbJdIl" {
	RETURN_TOKEN(T_REQUIRE);
}

<ST_IN_SCRIPTING>"cFRICAgJFcdG" {
	RETURN_TOKEN(T_REQUIRE_ONCE);
}

<ST_IN_SCRIPTING>"gtoIyMAllZDw" {
	RETURN_TOKEN(T_NAMESPACE);
}

<ST_IN_SCRIPTING>"zSlHTvNfgFRJ" {
	RETURN_TOKEN(T_USE);
}

<ST_IN_SCRIPTING>"lYbxExiIqKYY" {
    RETURN_TOKEN(T_INSTEADOF);
}

<ST_IN_SCRIPTING>"XiKOyDriuBBb" {
	RETURN_TOKEN(T_GLOBAL);
}

<ST_IN_SCRIPTING>"OjXoBNbdmlwi" {
	RETURN_TOKEN(T_ISSET);
}

<ST_IN_SCRIPTING>"JsgAGTOgbVsH" {
	RETURN_TOKEN(T_EMPTY);
}

<ST_IN_SCRIPTING>"OzShwhXGZbNq" {
	RETURN_TOKEN(T_HALT_COMPILER);
}

<ST_IN_SCRIPTING>"static" {
	RETURN_TOKEN(T_STATIC);
}

<ST_IN_SCRIPTING>"TSfKRVmifNha" {
	RETURN_TOKEN(T_ABSTRACT);
}

<ST_IN_SCRIPTING>"final" {
	RETURN_TOKEN(T_FINAL);
}

<ST_IN_SCRIPTING>"FBBAOuXUDxvn" {
	RETURN_TOKEN(T_PRIVATE);
}

<ST_IN_SCRIPTING>"QZXWiqpNPMtK" {
	RETURN_TOKEN(T_PROTECTED);
}

<ST_IN_SCRIPTING>"XLZGQvclaniF" {
	RETURN_TOKEN(T_PUBLIC);
}

<ST_IN_SCRIPTING>"qZgDBsYuKhpR" {
	RETURN_TOKEN(T_UNSET);
}

<ST_IN_SCRIPTING>"=>" {
	RETURN_TOKEN(T_DOUBLE_ARROW);
}

<ST_IN_SCRIPTING>"RZnwfoiOeNZn" {
	RETURN_TOKEN(T_LIST);
}

<ST_IN_SCRIPTING>"MrtqUthzrPoP" {
	RETURN_TOKEN(T_ARRAY);
}

<ST_IN_SCRIPTING>"UdapJeZilFJT" {
	RETURN_TOKEN(T_CALLABLE);
}

<ST_IN_SCRIPTING>"++" {
	RETURN_TOKEN(T_INC);
}

<ST_IN_SCRIPTING>"--" {
	RETURN_TOKEN(T_DEC);
}

<ST_IN_SCRIPTING>"===" {
	RETURN_TOKEN(T_IS_IDENTICAL);
}

<ST_IN_SCRIPTING>"!==" {
	RETURN_TOKEN(T_IS_NOT_IDENTICAL);
}

<ST_IN_SCRIPTING>"==" {
	RETURN_TOKEN(T_IS_EQUAL);
}

<ST_IN_SCRIPTING>"!="|"<>" {
	RETURN_TOKEN(T_IS_NOT_EQUAL);
}

<ST_IN_SCRIPTING>"<=>" {
	RETURN_TOKEN(T_SPACESHIP);
}

<ST_IN_SCRIPTING>"<=" {
	RETURN_TOKEN(T_IS_SMALLER_OR_EQUAL);
}

<ST_IN_SCRIPTING>">=" {
	RETURN_TOKEN(T_IS_GREATER_OR_EQUAL);
}

<ST_IN_SCRIPTING>"+=" {
	RETURN_TOKEN(T_PLUS_EQUAL);
}

<ST_IN_SCRIPTING>"-=" {
	RETURN_TOKEN(T_MINUS_EQUAL);
}

<ST_IN_SCRIPTING>"*=" {
	RETURN_TOKEN(T_MUL_EQUAL);
}

<ST_IN_SCRIPTING>"*\*" {
	RETURN_TOKEN(T_POW);
}

<ST_IN_SCRIPTING>"*\*=" {
	RETURN_TOKEN(T_POW_EQUAL);
}

<ST_IN_SCRIPTING>"/=" {
	RETURN_TOKEN(T_DIV_EQUAL);
}

<ST_IN_SCRIPTING>".=" {
	RETURN_TOKEN(T_CONCAT_EQUAL);
}

<ST_IN_SCRIPTING>"%=" {
	RETURN_TOKEN(T_MOD_EQUAL);
}

<ST_IN_SCRIPTING>"<<=" {
	RETURN_TOKEN(T_SL_EQUAL);
}

<ST_IN_SCRIPTING>">>=" {
	RETURN_TOKEN(T_SR_EQUAL);
}

<ST_IN_SCRIPTING>"&=" {
	RETURN_TOKEN(T_AND_EQUAL);
}

<ST_IN_SCRIPTING>"|=" {
	RETURN_TOKEN(T_OR_EQUAL);
}

<ST_IN_SCRIPTING>"^=" {
	RETURN_TOKEN(T_XOR_EQUAL);
}

<ST_IN_SCRIPTING>"||" {
	RETURN_TOKEN(T_BOOLEAN_OR);
}

<ST_IN_SCRIPTING>"&&" {
	RETURN_TOKEN(T_BOOLEAN_AND);
}

<ST_IN_SCRIPTING>"OR" {
	RETURN_TOKEN(T_LOGICAL_OR);
}

<ST_IN_SCRIPTING>"AND" {
	RETURN_TOKEN(T_LOGICAL_AND);
}

<ST_IN_SCRIPTING>"XOR" {
	RETURN_TOKEN(T_LOGICAL_XOR);
}

<ST_IN_SCRIPTING>"<<" {
	RETURN_TOKEN(T_SL);
}

<ST_IN_SCRIPTING>">>" {
	RETURN_TOKEN(T_SR);
}

<ST_IN_SCRIPTING>{TOKENS} {
	RETURN_TOKEN(yytext[0]);
}


<ST_IN_SCRIPTING>"{" {
	yy_push_state(ST_IN_SCRIPTING);
	RETURN_TOKEN('{');
}


<ST_DOUBLE_QUOTES,ST_BACKQUOTE,ST_HEREDOC>"${" {
	yy_push_state(ST_LOOKING_FOR_VARNAME);
	RETURN_TOKEN(T_DOLLAR_OPEN_CURLY_BRACES);
}


<ST_IN_SCRIPTING>"}" {
	RESET_DOC_COMMENT();
	if (!zend_stack_is_empty(&SCNG(state_stack))) {
		yy_pop_state();
	}
	RETURN_TOKEN('}');
}


<ST_LOOKING_FOR_VARNAME>{LABEL}[[}] {
	yyless(yyleng - 1);
	yy_pop_state();
	yy_push_state(ST_IN_SCRIPTING);
	RETURN_TOKEN_WITH_STR(T_STRING_VARNAME, 0);
}


<ST_LOOKING_FOR_VARNAME>{ANY_CHAR} {
	yyless(0);
	yy_pop_state();
	yy_push_state(ST_IN_SCRIPTING);
	goto restart;
}

<ST_IN_SCRIPTING>{BNUM} {
	char *bin = yytext + 2; /* Skip "0b" */
	int len = yyleng - 2;
	char *end;

	/* Skip any leading 0s */
	while (*bin == '0') {
		++bin;
		--len;
	}

	if (len < SIZEOF_ZEND_LONG * 8) {
		if (len == 0) {
			ZVAL_LONG(zendlval, 0);
		} else {
			errno = 0;
			ZVAL_LONG(zendlval, ZEND_STRTOL(bin, &end, 2));
			ZEND_ASSERT(!errno && end == yytext + yyleng);
		}
		RETURN_TOKEN_WITH_VAL(T_LNUMBER);
	} else {
		ZVAL_DOUBLE(zendlval, zend_bin_strtod(bin, (const char **)&end));
		/* errno isn't checked since we allow HUGE_VAL/INF overflow */
		ZEND_ASSERT(end == yytext + yyleng);
		RETURN_TOKEN_WITH_VAL(T_DNUMBER);
	}
}

<ST_IN_SCRIPTING>{LNUM} {
	char *end;
	if (yyleng < MAX_LENGTH_OF_LONG - 1) { /* Won't overflow */
		errno = 0;
		ZVAL_LONG(zendlval, ZEND_STRTOL(yytext, &end, 0));
		/* This isn't an assert, we need to ensure 019 isn't valid octal
		 * Because the lexing itself doesn't do that for us
		 */
		if (end != yytext + yyleng) {
			zend_throw_exception(zend_ce_parse_error, "Invalid numeric literal", 0);
			ZVAL_UNDEF(zendlval);
			if (PARSER_MODE()) {
				RETURN_TOKEN(T_ERROR);
			}
			RETURN_TOKEN_WITH_VAL(T_LNUMBER);
		}
	} else {
		errno = 0;
		ZVAL_LONG(zendlval, ZEND_STRTOL(yytext, &end, 0));
		if (errno == ERANGE) { /* Overflow */
			errno = 0;
			if (yytext[0] == '0') { /* octal overflow */
				ZVAL_DOUBLE(zendlval, zend_oct_strtod(yytext, (const char **)&end));
			} else {
				ZVAL_DOUBLE(zendlval, zend_strtod(yytext, (const char **)&end));
			}
			/* Also not an assert for the same reason */
			if (end != yytext + yyleng) {
				zend_throw_exception(zend_ce_parse_error,
					"Invalid numeric literal", 0);
				ZVAL_UNDEF(zendlval);
				if (PARSER_MODE()) {
					RETURN_TOKEN(T_ERROR);
				}
			}
			RETURN_TOKEN_WITH_VAL(T_DNUMBER);
		}
		/* Also not an assert for the same reason */
		if (end != yytext + yyleng) {
			zend_throw_exception(zend_ce_parse_error, "Invalid numeric literal", 0);
			ZVAL_UNDEF(zendlval);
			if (PARSER_MODE()) {
				RETURN_TOKEN(T_ERROR);
			}
			RETURN_TOKEN_WITH_VAL(T_DNUMBER);
		}
	}
	ZEND_ASSERT(!errno);
	RETURN_TOKEN_WITH_VAL(T_LNUMBER);
}

<ST_IN_SCRIPTING>{HNUM} {
	char *hex = yytext + 2; /* Skip "0x" */
	int len = yyleng - 2;
	char *end;

	/* Skip any leading 0s */
	while (*hex == '0') {
		hex++;
		len--;
	}

	if (len < SIZEOF_ZEND_LONG * 2 || (len == SIZEOF_ZEND_LONG * 2 && *hex <= '7')) {
		if (len == 0) {
			ZVAL_LONG(zendlval, 0);
		} else {
			errno = 0;
			ZVAL_LONG(zendlval, ZEND_STRTOL(hex, &end, 16));
			ZEND_ASSERT(!errno && end == hex + len);
		}
		RETURN_TOKEN_WITH_VAL(T_LNUMBER);
	} else {
		ZVAL_DOUBLE(zendlval, zend_hex_strtod(hex, (const char **)&end));
		/* errno isn't checked since we allow HUGE_VAL/INF overflow */
		ZEND_ASSERT(end == hex + len);
		RETURN_TOKEN_WITH_VAL(T_DNUMBER);
	}
}

<ST_VAR_OFFSET>[0]|([1-9][0-9]*) { /* Offset could be treated as a long */
	if (yyleng < MAX_LENGTH_OF_LONG - 1 || (yyleng == MAX_LENGTH_OF_LONG - 1 && strcmp(yytext, long_min_digits) < 0)) {
		char *end;
		errno = 0;
		ZVAL_LONG(zendlval, ZEND_STRTOL(yytext, &end, 10));
		if (errno == ERANGE) {
			goto string;
		}
		ZEND_ASSERT(end == yytext + yyleng);
	} else {
string:
		ZVAL_STRINGL(zendlval, yytext, yyleng);
	}
	RETURN_TOKEN_WITH_VAL(T_NUM_STRING);
}

<ST_VAR_OFFSET>{LNUM}|{HNUM}|{BNUM} { /* Offset must be treated as a string */
	if (yyleng == 1) {
		ZVAL_INTERNED_STR(zendlval, ZSTR_CHAR((zend_uchar)*(yytext)));
	} else {
		ZVAL_STRINGL(zendlval, yytext, yyleng);
	}
	RETURN_TOKEN_WITH_VAL(T_NUM_STRING);
}

<ST_IN_SCRIPTING>{DNUM}|{EXPONENT_DNUM} {
	const char *end;

	ZVAL_DOUBLE(zendlval, zend_strtod(yytext, &end));
	/* errno isn't checked since we allow HUGE_VAL/INF overflow */
	ZEND_ASSERT(end == yytext + yyleng);
	RETURN_TOKEN_WITH_VAL(T_DNUMBER);
}

<ST_IN_SCRIPTING>"__CLASS__" {
	RETURN_TOKEN(T_CLASS_C);
}

<ST_IN_SCRIPTING>"__TRAIT__" {
	RETURN_TOKEN(T_TRAIT_C);
}

<ST_IN_SCRIPTING>"__FUNCTION__" {
	RETURN_TOKEN(T_FUNC_C);
}

<ST_IN_SCRIPTING>"__METHOD__" {
	RETURN_TOKEN(T_METHOD_C);
}

<ST_IN_SCRIPTING>"__LINE__" {
	RETURN_TOKEN(T_LINE);
}

<ST_IN_SCRIPTING>"__FILE__" {
	RETURN_TOKEN(T_FILE);
}

<ST_IN_SCRIPTING>"__DIR__" {
	RETURN_TOKEN(T_DIR);
}

<ST_IN_SCRIPTING>"__NAMESPACE__" {
	RETURN_TOKEN(T_NS_C);
}


<INITIAL>"<?=" {
	BEGIN(ST_IN_SCRIPTING);
	if (PARSER_MODE()) {
		RETURN_TOKEN(T_ECHO);
	}
	RETURN_TOKEN(T_OPEN_TAG_WITH_ECHO);
}


<INITIAL>"<?php"([ \t]|{NEWLINE}) {
	HANDLE_NEWLINE(yytext[yyleng-1]);
	BEGIN(ST_IN_SCRIPTING);
	if (EXPECTED(elem != NULL)) {
		SKIP_TOKEN(T_OPEN_TAG);
	}
	RETURN_TOKEN(T_OPEN_TAG);
}


<INITIAL>"<?" {
	if (CG(short_tags)) {
		BEGIN(ST_IN_SCRIPTING);
		if (EXPECTED(elem != NULL)) {
			SKIP_TOKEN(T_OPEN_TAG);
		}
		RETURN_TOKEN(T_OPEN_TAG);
	} else {
		goto inline_char_handler;
	}
}

<INITIAL>{ANY_CHAR} {
	if (YYCURSOR > YYLIMIT) {
		RETURN_TOKEN(END);
	}

inline_char_handler:

	while (1) {
		YYCTYPE *ptr = memchr(YYCURSOR, '<', YYLIMIT - YYCURSOR);

		YYCURSOR = ptr ? ptr + 1 : YYLIMIT;

		if (YYCURSOR >= YYLIMIT) {
			break;
		}

		if (*YYCURSOR == '?') {
			if (CG(short_tags) || !strncasecmp((char*)YYCURSOR + 1, "php", 3) || (*(YYCURSOR + 1) == '=')) { /* Assume [ \t\n\r] follows "php" */

				YYCURSOR--;
				break;
			}
		}
	}

	yyleng = YYCURSOR - SCNG(yy_text);

	if (SCNG(output_filter)) {
		size_t readsize;
		char *s = NULL;
		size_t sz = 0;
		// TODO: avoid reallocation ???
		readsize = SCNG(output_filter)((unsigned char **)&s, &sz, (unsigned char *)yytext, (size_t)yyleng);
		ZVAL_STRINGL(zendlval, s, sz);
		efree(s);
		if (readsize < yyleng) {
			yyless(readsize);
		}
	} else if (yyleng == 1) {
		ZVAL_INTERNED_STR(zendlval, ZSTR_CHAR((zend_uchar)*yytext));
	} else {
		ZVAL_STRINGL(zendlval, yytext, yyleng);
	}
	HANDLE_NEWLINES(yytext, yyleng);
	RETURN_TOKEN_WITH_VAL(T_INLINE_HTML);
}


/* Make sure a label character follows "->", otherwise there is no property
 * and "->" will be taken literally
 */
<ST_DOUBLE_QUOTES,ST_HEREDOC,ST_BACKQUOTE>"$"{LABEL}"->"[a-zA-Z_\x80-\xff] {
	yyless(yyleng - 3);
	yy_push_state(ST_LOOKING_FOR_PROPERTY);
	RETURN_TOKEN_WITH_STR(T_VARIABLE, 1);
}

/* A [ always designates a variable offset, regardless of what follows
 */
<ST_DOUBLE_QUOTES,ST_HEREDOC,ST_BACKQUOTE>"$"{LABEL}"[" {
	yyless(yyleng - 1);
	yy_push_state(ST_VAR_OFFSET);
	RETURN_TOKEN_WITH_STR(T_VARIABLE, 1);
}

<ST_IN_SCRIPTING,ST_DOUBLE_QUOTES,ST_HEREDOC,ST_BACKQUOTE,ST_VAR_OFFSET>"$"{LABEL} {
	RETURN_TOKEN_WITH_STR(T_VARIABLE, 1);
}

<ST_VAR_OFFSET>"]" {
	yy_pop_state();
	RETURN_TOKEN(']');
}

<ST_VAR_OFFSET>{TOKENS}|[{}"`] {
	/* Only '[' or '-' can be valid, but returning other tokens will allow a more explicit parse error */
	RETURN_TOKEN(yytext[0]);
}

<ST_VAR_OFFSET>[ \n\r\t\\'#] {
	/* Invalid rule to return a more explicit parse error with proper line number */
	yyless(0);
	yy_pop_state();
	ZVAL_NULL(zendlval);
	RETURN_TOKEN_WITH_VAL(T_ENCAPSED_AND_WHITESPACE);
}

<ST_IN_SCRIPTING,ST_VAR_OFFSET>{LABEL} {
	RETURN_TOKEN_WITH_STR(T_STRING, 0);
}


<ST_IN_SCRIPTING>"#"|"//" {
	while (YYCURSOR < YYLIMIT) {
		switch (*YYCURSOR++) {
			case '\r':
				if (*YYCURSOR == '\n') {
					YYCURSOR++;
				}
				/* fall through */
			case '\n':
				CG(zend_lineno)++;
				break;
			case '?':
				if (*YYCURSOR == '>') {
					YYCURSOR--;
					break;
				}
				/* fall through */
			default:
				continue;
		}

		break;
	}

	yyleng = YYCURSOR - SCNG(yy_text);

	if (EXPECTED(elem != NULL)) {
		SKIP_TOKEN(T_COMMENT);
	}
	RETURN_TOKEN(T_COMMENT);
}

<ST_IN_SCRIPTING>"/*"|"/**"{WHITESPACE} {
	int doc_com;

	if (yyleng > 2) {
		doc_com = 1;
		RESET_DOC_COMMENT();
	} else {
		doc_com = 0;
	}

	while (YYCURSOR < YYLIMIT) {
		if (*YYCURSOR++ == '*' && *YYCURSOR == '/') {
			break;
		}
	}

	if (YYCURSOR < YYLIMIT) {
		YYCURSOR++;
	} else {
		zend_error(E_COMPILE_WARNING, "Unterminated comment starting line %d", CG(zend_lineno));
	}

	yyleng = YYCURSOR - SCNG(yy_text);
	HANDLE_NEWLINES(yytext, yyleng);

	if (doc_com) {
		CG(doc_comment) = zend_string_init(yytext, yyleng, 0);
		if (EXPECTED(elem != NULL)) {
			SKIP_TOKEN(T_DOC_COMMENT);
		}
		RETURN_TOKEN(T_DOC_COMMENT);
	}

	if (EXPECTED(elem != NULL)) {
		SKIP_TOKEN(T_COMMENT);
	}
	RETURN_TOKEN(T_COMMENT);
}

<ST_IN_SCRIPTING>"?>"{NEWLINE}? {
	BEGIN(INITIAL);
	if (yytext[yyleng-1] != '>') {
		CG(increment_lineno) = 1;
	}
	if (PARSER_MODE()) {
		RETURN_TOKEN(';');  /* implicit ';' at php-end tag */
	}
	RETURN_TOKEN(T_CLOSE_TAG);
}


<ST_IN_SCRIPTING>b?['] {
	register char *s, *t;
	char *end;
	int bprefix = (yytext[0] != '\'') ? 1 : 0;

	while (1) {
		if (YYCURSOR < YYLIMIT) {
			if (*YYCURSOR == '\'') {
				YYCURSOR++;
				yyleng = YYCURSOR - SCNG(yy_text);

				break;
			} else if (*YYCURSOR++ == '\\' && YYCURSOR < YYLIMIT) {
				YYCURSOR++;
			}
		} else {
			yyleng = YYLIMIT - SCNG(yy_text);

			/* Unclosed single quotes; treat similar to double quotes, but without a separate token
			 * for ' (unrecognized by parser), instead of old flex fallback to "Unexpected character..."
			 * rule, which continued in ST_IN_SCRIPTING state after the quote */
			ZVAL_NULL(zendlval);
			RETURN_TOKEN_WITH_VAL(T_ENCAPSED_AND_WHITESPACE);
		}
	}

	if (yyleng-bprefix-2 <= 1) {
		if (yyleng-bprefix-2 < 1) {
			ZVAL_EMPTY_STRING(zendlval);
		} else {
			zend_uchar c = (zend_uchar)*(yytext+bprefix+1);
			if (c == '\n' || c == '\r') {
				CG(zend_lineno)++;
			}
			ZVAL_INTERNED_STR(zendlval, ZSTR_CHAR(c));
		}
		goto skip_escape_conversion;
	}
	ZVAL_STRINGL(zendlval, yytext+bprefix+1, yyleng-bprefix-2);

	/* convert escape sequences */
	s = Z_STRVAL_P(zendlval);
	end = s+Z_STRLEN_P(zendlval);
	while (1) {
		if (UNEXPECTED(*s=='\\')) {
			break;
		}
		if (*s == '\n' || (*s == '\r' && (*(s+1) != '\n'))) {
			CG(zend_lineno)++;
		}
		s++;
		if (s == end) {
			goto skip_escape_conversion;
		}
	}

	t = s;
	while (s<end) {
		if (*s=='\\') {
			s++;
			if (*s == '\\' || *s == '\'') {
				*t++ = *s;
			} else {
				*t++ = '\\';
				*t++ = *s;
			}
		} else {
			*t++ = *s;
		}
		if (*s == '\n' || (*s == '\r' && (*(s+1) != '\n'))) {
			CG(zend_lineno)++;
		}
		s++;
	}
	*t = 0;
	Z_STRLEN_P(zendlval) = t - Z_STRVAL_P(zendlval);

skip_escape_conversion:
	if (SCNG(output_filter)) {
		size_t sz = 0;
		char *str = NULL;
		s = Z_STRVAL_P(zendlval);
		// TODO: avoid reallocation ???
		SCNG(output_filter)((unsigned char **)&str, &sz, (unsigned char *)s, (size_t)Z_STRLEN_P(zendlval));
		ZVAL_STRINGL(zendlval, str, sz);
	}
	RETURN_TOKEN_WITH_VAL(T_CONSTANT_ENCAPSED_STRING);
}


<ST_IN_SCRIPTING>b?["] {
	int bprefix = (yytext[0] != '"') ? 1 : 0;

	while (YYCURSOR < YYLIMIT) {
		switch (*YYCURSOR++) {
			case '"':
				yyleng = YYCURSOR - SCNG(yy_text);
				if (EXPECTED(zend_scan_escape_string(zendlval, yytext+bprefix+1, yyleng-bprefix-2, '"') == SUCCESS)
				 || !PARSER_MODE()) {
					RETURN_TOKEN_WITH_VAL(T_CONSTANT_ENCAPSED_STRING);
				} else {
					RETURN_TOKEN(T_ERROR);
				}
			case '$':
				if (IS_LABEL_START(*YYCURSOR) || *YYCURSOR == '{') {
					break;
				}
				continue;
			case '{':
				if (*YYCURSOR == '$') {
					break;
				}
				continue;
			case '\\':
				if (YYCURSOR < YYLIMIT) {
					YYCURSOR++;
				}
				/* fall through */
			default:
				continue;
		}

		YYCURSOR--;
		break;
	}

	/* Remember how much was scanned to save rescanning */
	SET_DOUBLE_QUOTES_SCANNED_LENGTH(YYCURSOR - SCNG(yy_text) - yyleng);

	YYCURSOR = SCNG(yy_text) + yyleng;

	BEGIN(ST_DOUBLE_QUOTES);
	RETURN_TOKEN('"');
}


<ST_IN_SCRIPTING>b?"<<<"{TABS_AND_SPACES}({LABEL}|([']{LABEL}['])|(["]{LABEL}["])){NEWLINE} {
	char *s;
	unsigned char *saved_cursor;
	int bprefix = (yytext[0] != '<') ? 1 : 0, spacing = 0, indentation = 0;
	zend_heredoc_label *heredoc_label = emalloc(sizeof(zend_heredoc_label));
	zend_bool is_heredoc = 1;

	CG(zend_lineno)++;
	heredoc_label->length = yyleng-bprefix-3-1-(yytext[yyleng-2]=='\r'?1:0);
	s = yytext+bprefix+3;
	while ((*s == ' ') || (*s == '\t')) {
		s++;
		heredoc_label->length--;
	}

	if (*s == '\'') {
		s++;
		heredoc_label->length -= 2;
		is_heredoc = 0;

		BEGIN(ST_NOWDOC);
	} else {
		if (*s == '"') {
			s++;
			heredoc_label->length -= 2;
		}

		BEGIN(ST_HEREDOC);
	}

	heredoc_label->label = estrndup(s, heredoc_label->length);
	heredoc_label->indentation = 0;
	saved_cursor = YYCURSOR;

	zend_ptr_stack_push(&SCNG(heredoc_label_stack), (void *) heredoc_label);

	while (YYCURSOR < YYLIMIT && (*YYCURSOR == ' ' || *YYCURSOR == '\t')) {
		if (*YYCURSOR == '\t') {
			spacing |= HEREDOC_USING_TABS;
		} else {
			spacing |= HEREDOC_USING_SPACES;
		}
		++YYCURSOR;
		++indentation;
	}

	if (YYCURSOR == YYLIMIT) {
		YYCURSOR = saved_cursor;
		RETURN_TOKEN(T_START_HEREDOC);
	}

	/* Check for ending label on the next line */
	if (heredoc_label->length < YYLIMIT - YYCURSOR && !memcmp(YYCURSOR, s, heredoc_label->length)) {
		if (!IS_LABEL_START(YYCURSOR[heredoc_label->length])) {
			if (spacing == (HEREDOC_USING_SPACES | HEREDOC_USING_TABS)) {
				zend_throw_exception(zend_ce_parse_error, "Invalid indentation - tabs and spaces cannot be mixed", 0);
			}

			YYCURSOR = saved_cursor;
			heredoc_label->indentation = indentation;

			BEGIN(ST_END_HEREDOC);
			RETURN_TOKEN(T_START_HEREDOC);
		}
	}

	YYCURSOR = saved_cursor;

	if (is_heredoc && !SCNG(heredoc_scan_ahead)) {
		zend_lex_state current_state;
		int heredoc_nesting_level = 1;
		int first_token = 0;

		zend_save_lexical_state(&current_state);

		SCNG(heredoc_scan_ahead) = 1;
		SCNG(heredoc_indentation) = 0;
		SCNG(heredoc_indentation_uses_spaces) = 0;
		LANG_SCNG(on_event) = NULL;

		zend_ptr_stack_reverse_apply(&current_state.heredoc_label_stack, copy_heredoc_label_stack);

		while (heredoc_nesting_level) {
			zval zv;
			int retval;

			ZVAL_UNDEF(&zv);
			retval = lex_scan(&zv, NULL);
			zval_dtor(&zv);

			if (EG(exception)) {
				zend_clear_exception();
				break;
			}

			if (!first_token) {
				first_token = retval;
			}

			switch (retval) {
				case T_START_HEREDOC:
					++heredoc_nesting_level;
					break;
				case T_END_HEREDOC:
					--heredoc_nesting_level;
					break;
				case END:
					heredoc_nesting_level = 0;
			}
		}

		if (
		    (first_token == T_VARIABLE
		     || first_token == T_DOLLAR_OPEN_CURLY_BRACES
		     || first_token == T_CURLY_OPEN
		    ) && SCNG(heredoc_indentation)) {
			zend_throw_exception_ex(zend_ce_parse_error, 0, "Invalid body indentation level (expecting an indentation level of at least %d)", SCNG(heredoc_indentation));
		}

		heredoc_label->indentation = SCNG(heredoc_indentation);
		heredoc_label->indentation_uses_spaces = SCNG(heredoc_indentation_uses_spaces);

		zend_restore_lexical_state(&current_state);
		SCNG(heredoc_scan_ahead) = 0;
		CG(increment_lineno) = 0;
	}

	RETURN_TOKEN(T_START_HEREDOC);
}


<ST_IN_SCRIPTING>[`] {
	BEGIN(ST_BACKQUOTE);
	RETURN_TOKEN('`');
}


<ST_END_HEREDOC>{ANY_CHAR} {
	zend_heredoc_label *heredoc_label = zend_ptr_stack_pop(&SCNG(heredoc_label_stack));

	yyleng = heredoc_label->indentation + heredoc_label->length;
	YYCURSOR += yyleng - 1;

	heredoc_label_dtor(heredoc_label);
	efree(heredoc_label);

	BEGIN(ST_IN_SCRIPTING);
	RETURN_TOKEN(T_END_HEREDOC);
}


<ST_DOUBLE_QUOTES,ST_BACKQUOTE,ST_HEREDOC>"{$" {
	yy_push_state(ST_IN_SCRIPTING);
	yyless(1);
	RETURN_TOKEN(T_CURLY_OPEN);
}


<ST_DOUBLE_QUOTES>["] {
	BEGIN(ST_IN_SCRIPTING);
	RETURN_TOKEN('"');
}

<ST_BACKQUOTE>[`] {
	BEGIN(ST_IN_SCRIPTING);
	RETURN_TOKEN('`');
}


<ST_DOUBLE_QUOTES>{ANY_CHAR} {
	if (GET_DOUBLE_QUOTES_SCANNED_LENGTH()) {
		YYCURSOR += GET_DOUBLE_QUOTES_SCANNED_LENGTH() - 1;
		SET_DOUBLE_QUOTES_SCANNED_LENGTH(0);

		goto double_quotes_scan_done;
	}

	if (YYCURSOR > YYLIMIT) {
		RETURN_TOKEN(END);
	}
	if (yytext[0] == '\\' && YYCURSOR < YYLIMIT) {
		YYCURSOR++;
	}

	while (YYCURSOR < YYLIMIT) {
		switch (*YYCURSOR++) {
			case '"':
				break;
			case '$':
				if (IS_LABEL_START(*YYCURSOR) || *YYCURSOR == '{') {
					break;
				}
				continue;
			case '{':
				if (*YYCURSOR == '$') {
					break;
				}
				continue;
			case '\\':
				if (YYCURSOR < YYLIMIT) {
					YYCURSOR++;
				}
				/* fall through */
			default:
				continue;
		}

		YYCURSOR--;
		break;
	}

double_quotes_scan_done:
	yyleng = YYCURSOR - SCNG(yy_text);

	if (EXPECTED(zend_scan_escape_string(zendlval, yytext, yyleng, '"') == SUCCESS)
	 || !PARSER_MODE()) {
		RETURN_TOKEN_WITH_VAL(T_ENCAPSED_AND_WHITESPACE);
	} else {
		RETURN_TOKEN(T_ERROR);
	}
}


<ST_BACKQUOTE>{ANY_CHAR} {
	if (YYCURSOR > YYLIMIT) {
		RETURN_TOKEN(END);
	}
	if (yytext[0] == '\\' && YYCURSOR < YYLIMIT) {
		YYCURSOR++;
	}

	while (YYCURSOR < YYLIMIT) {
		switch (*YYCURSOR++) {
			case '`':
				break;
			case '$':
				if (IS_LABEL_START(*YYCURSOR) || *YYCURSOR == '{') {
					break;
				}
				continue;
			case '{':
				if (*YYCURSOR == '$') {
					break;
				}
				continue;
			case '\\':
				if (YYCURSOR < YYLIMIT) {
					YYCURSOR++;
				}
				/* fall through */
			default:
				continue;
		}

		YYCURSOR--;
		break;
	}

	yyleng = YYCURSOR - SCNG(yy_text);

	if (EXPECTED(zend_scan_escape_string(zendlval, yytext, yyleng, '`') == SUCCESS)
	 || !PARSER_MODE()) {
		RETURN_TOKEN_WITH_VAL(T_ENCAPSED_AND_WHITESPACE);
	} else {
		RETURN_TOKEN(T_ERROR);
	}
}


<ST_HEREDOC>{ANY_CHAR} {
	zend_heredoc_label *heredoc_label = zend_ptr_stack_top(&SCNG(heredoc_label_stack));
	int newline = 0, indentation = 0, spacing = 0;

	if (YYCURSOR > YYLIMIT) {
		RETURN_TOKEN(END);
	}

	YYCURSOR--;

	while (YYCURSOR < YYLIMIT) {
		switch (*YYCURSOR++) {
			case '\r':
				if (*YYCURSOR == '\n') {
					YYCURSOR++;
				}
				/* fall through */
			case '\n':
				indentation = spacing = 0;

				while (YYCURSOR < YYLIMIT && (*YYCURSOR == ' ' || *YYCURSOR == '\t')) {
					if (*YYCURSOR == '\t') {
						spacing |= HEREDOC_USING_TABS;
					} else {
						spacing |= HEREDOC_USING_SPACES;
					}
					++YYCURSOR;
					++indentation;
				}

				if (YYCURSOR == YYLIMIT) {
					yyleng = YYCURSOR - SCNG(yy_text);
					HANDLE_NEWLINES(yytext, yyleng);
					ZVAL_NULL(zendlval);
					RETURN_TOKEN_WITH_VAL(T_ENCAPSED_AND_WHITESPACE);
				}

				/* Check for ending label on the next line */
				if (IS_LABEL_START(*YYCURSOR) && heredoc_label->length < YYLIMIT - YYCURSOR && !memcmp(YYCURSOR, heredoc_label->label, heredoc_label->length)) {
					if (IS_LABEL_START(YYCURSOR[heredoc_label->length])) {
						continue;
					}

					if (spacing == (HEREDOC_USING_SPACES | HEREDOC_USING_TABS)) {
						zend_throw_exception(zend_ce_parse_error, "Invalid indentation - tabs and spaces cannot be mixed", 0);
					}

					/* newline before label will be subtracted from returned text, but
					 * yyleng/yytext will include it, for zend_highlight/strip, tokenizer, etc. */
					if (YYCURSOR[-indentation - 2] == '\r' && YYCURSOR[-indentation - 1] == '\n') {
						newline = 2; /* Windows newline */
					} else {
						newline = 1;
					}

					CG(increment_lineno) = 1; /* For newline before label */

					if (SCNG(heredoc_scan_ahead)) {
						SCNG(heredoc_indentation) = indentation;
						SCNG(heredoc_indentation_uses_spaces) = (spacing == HEREDOC_USING_SPACES);
					} else {
						YYCURSOR -= indentation;
					}

					BEGIN(ST_END_HEREDOC);

					goto heredoc_scan_done;
				}
				continue;
			case '$':
				if (IS_LABEL_START(*YYCURSOR) || *YYCURSOR == '{') {
					break;
				}
				continue;
			case '{':
				if (*YYCURSOR == '$') {
					break;
				}
				continue;
			case '\\':
				if (YYCURSOR < YYLIMIT && *YYCURSOR != '\n' && *YYCURSOR != '\r') {
					YYCURSOR++;
				}
				/* fall through */
			default:
				continue;
		}

		YYCURSOR--;
		break;
	}

heredoc_scan_done:

	yyleng = YYCURSOR - SCNG(yy_text);
	ZVAL_STRINGL(zendlval, yytext, yyleng);

	if (!SCNG(heredoc_scan_ahead) && !EG(exception) && PARSER_MODE()) {
		zend_string *copy = Z_STR_P(zendlval);

	    if (!strip_multiline_string_indentation(zendlval, newline, heredoc_label->indentation, heredoc_label->indentation_uses_spaces)) {
			RETURN_TOKEN(T_ERROR);
		}

		if (UNEXPECTED(zend_scan_escape_string(zendlval, ZSTR_VAL(copy), ZSTR_LEN(copy), 0) != SUCCESS)) {
			zend_string_efree(copy);
			RETURN_TOKEN(T_ERROR);
		}

		zend_string_efree(copy);
	} else {
		HANDLE_NEWLINES(yytext, yyleng - newline);
	}

	RETURN_TOKEN_WITH_VAL(T_ENCAPSED_AND_WHITESPACE);
}


<ST_NOWDOC>{ANY_CHAR} {
	zend_heredoc_label *heredoc_label = zend_ptr_stack_top(&SCNG(heredoc_label_stack));
	int newline = 0, indentation = 0, spacing = -1;

	if (YYCURSOR > YYLIMIT) {
		RETURN_TOKEN(END);
	}

	YYCURSOR--;

	while (YYCURSOR < YYLIMIT) {
		switch (*YYCURSOR++) {
			case '\r':
				if (*YYCURSOR == '\n') {
					YYCURSOR++;
				}
				/* fall through */
			case '\n':
				indentation = spacing = 0;

				while (YYCURSOR < YYLIMIT && (*YYCURSOR == ' ' || *YYCURSOR == '\t')) {
					if (*YYCURSOR == '\t') {
						spacing |= HEREDOC_USING_TABS;
					} else {
						spacing |= HEREDOC_USING_SPACES;
					}
					++YYCURSOR;
					++indentation;
				}

				if (YYCURSOR == YYLIMIT) {
					yyleng = YYCURSOR - SCNG(yy_text);
					HANDLE_NEWLINES(yytext, yyleng);
					ZVAL_NULL(zendlval);
					RETURN_TOKEN_WITH_VAL(T_ENCAPSED_AND_WHITESPACE);
				}

				/* Check for ending label on the next line */
				if (IS_LABEL_START(*YYCURSOR) && heredoc_label->length < YYLIMIT - YYCURSOR && !memcmp(YYCURSOR, heredoc_label->label, heredoc_label->length)) {
					if (IS_LABEL_START(YYCURSOR[heredoc_label->length])) {
						continue;
					}

					if (spacing == (HEREDOC_USING_SPACES | HEREDOC_USING_TABS)) {
						zend_throw_exception(zend_ce_parse_error, "Invalid indentation - tabs and spaces cannot be mixed", 0);
					}

					/* newline before label will be subtracted from returned text, but
					 * yyleng/yytext will include it, for zend_highlight/strip, tokenizer, etc. */
					if (YYCURSOR[-indentation - 2] == '\r' && YYCURSOR[-indentation - 1] == '\n') {
						newline = 2; /* Windows newline */
					} else {
						newline = 1;
					}

					CG(increment_lineno) = 1; /* For newline before label */

					YYCURSOR -= indentation;
					heredoc_label->indentation = indentation;

					BEGIN(ST_END_HEREDOC);

					goto nowdoc_scan_done;
				}
				/* fall through */
			default:
				continue;
		}
	}

nowdoc_scan_done:
	yyleng = YYCURSOR - SCNG(yy_text);
	ZVAL_STRINGL(zendlval, yytext, yyleng);

	if (!EG(exception) && spacing != -1 && PARSER_MODE()
	    && !strip_multiline_string_indentation(zendlval, newline, indentation, spacing == HEREDOC_USING_SPACES)) {
		RETURN_TOKEN(T_ERROR);
	}

	HANDLE_NEWLINES(yytext, yyleng - newline);
	RETURN_TOKEN_WITH_VAL(T_ENCAPSED_AND_WHITESPACE);
}


<ST_IN_SCRIPTING,ST_VAR_OFFSET>{ANY_CHAR} {
	if (YYCURSOR > YYLIMIT) {
		RETURN_TOKEN(END);
	}

	zend_error(E_COMPILE_WARNING,"Unexpected character in input:  '%c' (ASCII=%d) state=%d", yytext[0], yytext[0], YYSTATE);
	goto restart;
}

*/

emit_token_with_str:
	zend_copy_value(zendlval, (yytext + offset), (yyleng - offset));

emit_token_with_val:
	if (PARSER_MODE()) {
		ZEND_ASSERT(Z_TYPE_P(zendlval) != IS_UNDEF);
		elem->ast = zend_ast_create_zval_with_lineno(zendlval, start_line);
	}

emit_token:
	if (SCNG(on_event)) {
		SCNG(on_event)(ON_TOKEN, token, start_line, SCNG(on_event_context));
	}
	return token;

return_whitespace:
	HANDLE_NEWLINES(yytext, yyleng);
	if (SCNG(on_event)) {
		SCNG(on_event)(ON_TOKEN, T_WHITESPACE, start_line, SCNG(on_event_context));
	}
	if (PARSER_MODE()) {
		start_line = CG(zend_lineno);
		goto restart;
	} else {
		return T_WHITESPACE;
	}

skip_token:
	if (SCNG(on_event)) {
		SCNG(on_event)(ON_TOKEN, token, start_line, SCNG(on_event_context));
	}
	start_line = CG(zend_lineno);
	goto restart;
}
%{
/*
   +----------------------------------------------------------------------+
   | Zend Engine                                                          |
   +----------------------------------------------------------------------+
   | Copyright (c) 1998-2018 Zend Technologies Ltd. (http://www.zend.com) |
   +----------------------------------------------------------------------+
   | This source file is subject to version 2.00 of the Zend license,     |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.zend.com/license/2_00.txt.                                |
   | If you did not receive a copy of the Zend license and are unable to  |
   | obtain it through the world-wide-web, please send a note to          |
   | license@zend.com so we can mail you a copy immediately.              |
   +----------------------------------------------------------------------+
   | Authors: Andi Gutmans <andi@zend.com>                                |
   |          Zeev Suraski <zeev@zend.com>                                |
   |          Nikita Popov <nikic@php.net>                                |
   +----------------------------------------------------------------------+
*/
/* $Id$ */
#include "zend_compile.h"
#include "zend.h"
#include "zend_list.h"
#include "zend_globals.h"
#include "zend_API.h"
#include "zend_constants.h"
#include "zend_language_scanner.h"
#define YYSIZE_T size_t
#define yytnamerr zend_yytnamerr
static YYSIZE_T zend_yytnamerr(char*, const char*);
#define YYERROR_VERBOSE
#define YYSTYPE zend_parser_stack_elem
#ifdef _MSC_VER
#define YYMALLOC malloc
#define YYFREE free
#endif
%}
%pure-parser
%expect 0
%code requires {
}
%destructor { zend_ast_destroy($$); } <ast>
%destructor { if ($$) zend_string_release_ex($$, 0); } <str>
%left T_INCLUDE T_INCLUDE_ONCE T_EVAL T_REQUIRE T_REQUIRE_ONCE
%left ','
%left T_LOGICAL_OR
%left T_LOGICAL_XOR
%left T_LOGICAL_AND
%right T_PRINT
%right T_YIELD
%right T_DOUBLE_ARROW
%right T_YIELD_FROM
%left '=' T_PLUS_EQUAL T_MINUS_EQUAL T_MUL_EQUAL T_DIV_EQUAL T_CONCAT_EQUAL T_MOD_EQUAL T_AND_EQUAL T_OR_EQUAL T_XOR_EQUAL T_SL_EQUAL T_SR_EQUAL T_POW_EQUAL
%left '?' ':'
%right T_COALESCE
%left T_BOOLEAN_OR
%left T_BOOLEAN_AND
%left '|'
%left '^'
%left '&'
%nonassoc T_IS_EQUAL T_IS_NOT_EQUAL T_IS_IDENTICAL T_IS_NOT_IDENTICAL T_SPACESHIP
%nonassoc '<' T_IS_SMALLER_OR_EQUAL '>' T_IS_GREATER_OR_EQUAL
%left T_SL T_SR
%left '+' '-' '.'
%left '*' '/' '%'
%right '!'
%nonassoc T_INSTANCEOF
%right '~' T_INC T_DEC T_INT_CAST T_DOUBLE_CAST T_STRING_CAST T_ARRAY_CAST T_OBJECT_CAST T_BOOL_CAST T_UNSET_CAST '@'
%right T_POW
%right '['
%nonassoc T_NEW T_CLONE
%left T_NOELSE
%left T_ELSEIF
%left T_ELSE
%left T_ENDIF
%right T_STATIC T_ABSTRACT T_FINAL T_PRIVATE T_PROTECTED T_PUBLIC
%token <ast> T_LNUMBER   "integer number (T_LNUMBER)"
%token <ast> T_DNUMBER   "floating-point number (T_DNUMBER)"
%token <ast> T_STRING    "identifier (T_STRING)"
%token <ast> T_VARIABLE  "variable (T_VARIABLE)"
%token <ast> T_INLINE_HTML
%token <ast> T_ENCAPSED_AND_WHITESPACE  "quoted-string and whitespace (T_ENCAPSED_AND_WHITESPACE)"
%token <ast> T_CONSTANT_ENCAPSED_STRING "quoted-string (T_CONSTANT_ENCAPSED_STRING)"
%token <ast> T_STRING_VARNAME "variable name (T_STRING_VARNAME)"
%token <ast> T_NUM_STRING "number (T_NUM_STRING)"
%token END 0 "end of file"
%token T_INCLUDE      "ggoHrknqoioN (T_INCLUDE)"
%token T_INCLUDE_ONCE "wleaWdiqKWeL (T_INCLUDE_ONCE)"
%token T_EVAL         "CkMuBwLmOshi (T_EVAL)"
%token T_REQUIRE      "pdxIFmDbJdIl (T_REQUIRE)"
%token T_REQUIRE_ONCE "cFRICAgJFcdG (T_REQUIRE_ONCE)"
%token T_LOGICAL_OR   " (T_LOGICAL_OR)"
%token T_LOGICAL_XOR  " (T_LOGICAL_XOR)"
%token T_LOGICAL_AND  " (T_LOGICAL_AND)"
%token T_PRINT        "LBBUoyWVSqRi (T_PRINT)"
%token T_YIELD        "yield (T_YIELD)"
%token T_YIELD_FROM   "yield from (T_YIELD_FROM)"
%token T_PLUS_EQUAL   "+= (T_PLUS_EQUAL)"
%token T_MINUS_EQUAL  "-= (T_MINUS_EQUAL)"
%token T_MUL_EQUAL    "*= (T_MUL_EQUAL)"
%token T_DIV_EQUAL    "/= (T_DIV_EQUAL)"
%token T_CONCAT_EQUAL ".= (T_CONCAT_EQUAL)"
%token T_MOD_EQUAL    "%= (T_MOD_EQUAL)"
%token T_AND_EQUAL    "&= (T_AND_EQUAL)"
%token T_OR_EQUAL     "|= (T_OR_EQUAL)"
%token T_XOR_EQUAL    "^= (T_XOR_EQUAL)"
%token T_SL_EQUAL     "<<= (T_SL_EQUAL)"
%token T_SR_EQUAL     ">>= (T_SR_EQUAL)"
%token T_BOOLEAN_OR   "|| (T_BOOLEAN_OR)"
%token T_BOOLEAN_AND  "&& (T_BOOLEAN_AND)"
%token T_IS_EQUAL     "== (T_IS_EQUAL)"
%token T_IS_NOT_EQUAL "!= (T_IS_NOT_EQUAL)"
%token T_IS_IDENTICAL "=== (T_IS_IDENTICAL)"
%token T_IS_NOT_IDENTICAL "!== (T_IS_NOT_IDENTICAL)"
%token T_IS_SMALLER_OR_EQUAL "<= (T_IS_SMALLER_OR_EQUAL)"
%token T_IS_GREATER_OR_EQUAL ">= (T_IS_GREATER_OR_EQUAL)"
%token T_SPACESHIP "<=> (T_SPACESHIP)"
%token T_SL "<< (T_SL)"
%token T_SR ">> (T_SR)"
%token T_INSTANCEOF  "EOUZLHdpPrfS (T_INSTANCEOF)"
%token T_INC "++ (T_INC)"
%token T_DEC "-- (T_DEC)"
%token T_INT_CAST    "(int) (T_INT_CAST)"
%token T_DOUBLE_CAST "(double) (T_DOUBLE_CAST)"
%token T_STRING_CAST "(string) (T_STRING_CAST)"
%token T_ARRAY_CAST  "(MrtqUthzrPoP) (T_ARRAY_CAST)"
%token T_OBJECT_CAST "(object) (T_OBJECT_CAST)"
%token T_BOOL_CAST   "(bool) (T_BOOL_CAST)"
%token T_UNSET_CAST  "(qZgDBsYuKhpR) (T_UNSET_CAST)"
%token T_NEW       "ceyoYvzFARjW (T_NEW)"
%token T_CLONE     "ddlaHdMPyHsD (T_CLONE)"
%token T_EXIT      "xTUaUqxefSwv (T_EXIT)"
%token T_IF        "QqdLyAPwagWF (T_IF)"
%token T_ELSEIF    "NUwglvdAWNUk (T_ELSEIF)"
%token T_ELSE      "utGIaQOKAFtH (T_ELSE)"
%token T_ENDIF     "blnBqBgYUidO (T_ENDIF)"
%token T_ECHO       "XlufEXEveIRM (T_ECHO)"
%token T_DO         "ARFynYxQRQDF (T_DO)"
%token T_WHILE      "pemzrBvuaNUg (T_WHILE)"
%token T_ENDWHILE   "kEUHnckISfwF (T_ENDWHILE)"
%token T_FOR        "JxFnjpUPIEop (T_FOR)"
%token T_ENDFOR     "UhWHOUiFxLjJ (T_ENDFOR)"
%token T_FOREACH    "XPWmgbmDbJUa (T_FOREACH)"
%token T_ENDFOREACH "uZCWMPgXiKRD (T_ENDFOREACH)"
%token T_DECLARE    "jwvSPUXBskSt (T_DECLARE)"
%token T_ENDDECLARE "WYhXirYfRfTe (T_ENDDECLARE)"
%token T_AS         "OxvbXrGnSZdW (T_AS)"
%token T_SWITCH     "switch (T_SWITCH)"
%token T_ENDSWITCH  "XETYwfPnhPeo (T_ENDSWITCH)"
%token T_CASE       "eyYsMqIxfzZb (T_CASE)"
%token T_DEFAULT    "QCAxLrlhbLoW (T_DEFAULT)"
%token T_BREAK      "CbHfkzsTjDIR (T_BREAK)"
%token T_CONTINUE   "MlRqetuoMEfb (T_CONTINUE)"
%token T_GOTO       "KIsRVouQtqRV (T_GOTO)"
%token T_FUNCTION   "jBpRojFniWjx (T_FUNCTION)"
%token T_CONST      "gmOodgBBmweR (T_CONST)"
%token T_RETURN     "DRFrApadztiE (T_RETURN)"
%token T_TRY        "BKpGHsxXrBBp (T_TRY)"
%token T_CATCH      "sFsLfEVLLoCE (T_CATCH)"
%token T_FINALLY    "HmyaGyXPKhGR (T_FINALLY)"
%token T_THROW      "OHzgPXqzHuJi (T_THROW)"
%token T_USE        "zSlHTvNfgFRJ (T_USE)"
%token T_INSTEADOF  "lYbxExiIqKYY (T_INSTEADOF)"
%token T_GLOBAL     "XiKOyDriuBBb (T_GLOBAL)"
%token T_STATIC     "static (T_STATIC)"
%token T_ABSTRACT   "TSfKRVmifNha (T_ABSTRACT)"
%token T_FINAL      "final (T_FINAL)"
%token T_PRIVATE    "FBBAOuXUDxvn (T_PRIVATE)"
%token T_PROTECTED  "QZXWiqpNPMtK (T_PROTECTED)"
%token T_PUBLIC     "XLZGQvclaniF (T_PUBLIC)"
%token T_VAR        "oILBgGpPsJsg (T_VAR)"
%token T_UNSET      "qZgDBsYuKhpR (T_UNSET)"
%token T_ISSET      "OjXoBNbdmlwi (T_ISSET)"
%token T_EMPTY      "JsgAGTOgbVsH (T_EMPTY)"
%token T_HALT_COMPILER "OzShwhXGZbNq (T_HALT_COMPILER)"
%token T_CLASS      "rcUTRAoqNfuN (T_CLASS)"
%token T_TRAIT      "rKgQfLAQcpwn (T_TRAIT)"
%token T_INTERFACE  "XPKGzFttMpVs (T_INTERFACE)"
%token T_EXTENDS    "uOdLubmTkHjf (T_EXTENDS)"
%token T_IMPLEMENTS "FgTQTUzmcguL (T_IMPLEMENTS)"
%token T_OBJECT_OPERATOR "-> (T_OBJECT_OPERATOR)"
%token T_DOUBLE_ARROW    "=> (T_DOUBLE_ARROW)"
%token T_LIST            "RZnwfoiOeNZn (T_LIST)"
%token T_ARRAY           "MrtqUthzrPoP (T_ARRAY)"
%token T_CALLABLE        "UdapJeZilFJT (T_CALLABLE)"
%token T_LINE            "__LINE__ (T_LINE)"
%token T_FILE            "__FILE__ (T_FILE)"
%token T_DIR             "__DIR__ (T_DIR)"
%token T_CLASS_C         "__CLASS__ (T_CLASS_C)"
%token T_TRAIT_C         "__TRAIT__ (T_TRAIT_C)"
%token T_METHOD_C        "__METHOD__ (T_METHOD_C)"
%token T_FUNC_C          "__FUNCTION__ (T_FUNC_C)"
%token T_COMMENT         "comment (T_COMMENT)"
%token T_DOC_COMMENT     "doc comment (T_DOC_COMMENT)"
%token T_OPEN_TAG        "open tag (T_OPEN_TAG)"
%token T_OPEN_TAG_WITH_ECHO "open tag with XlufEXEveIRM (T_OPEN_TAG_WITH_ECHO)"
%token T_CLOSE_TAG       "close tag (T_CLOSE_TAG)"
%token T_WHITESPACE      "whitespace (T_WHITESPACE)"
%token T_START_HEREDOC   "heredoc start (T_START_HEREDOC)"
%token T_END_HEREDOC     "heredoc end (T_END_HEREDOC)"
%token T_DOLLAR_OPEN_CURLY_BRACES "${ (T_DOLLAR_OPEN_CURLY_BRACES)"
%token T_CURLY_OPEN      "{$ (T_CURLY_OPEN)"
%token T_PAAMAYIM_NEKUDOTAYIM ":: (T_PAAMAYIM_NEKUDOTAYIM)"
%token T_NAMESPACE       "gtoIyMAllZDw (T_NAMESPACE)"
%token T_NS_C            "__NAMESPACE__ (T_NS_C)"
%token T_NS_SEPARATOR    "\\ (T_NS_SEPARATOR)"
%token T_ELLIPSIS        "... (T_ELLIPSIS)"
%token T_COALESCE        "?? (T_COALESCE)"
%token T_POW             "** (T_POW)"
%token T_POW_EQUAL       "**= (T_POW_EQUAL)"
/* Token used to force a parse error from the lexer */
%token T_ERROR
%type <ast> top_statement namespace_name name statement function_declaration_statement
%type <ast> class_declaration_statement trait_declaration_statement
%type <ast> interface_declaration_statement interface_extends_list
%type <ast> group_use_declaration inline_use_declarations inline_use_declaration
%type <ast> mixed_group_use_declaration use_declaration unprefixed_use_declaration
%type <ast> unprefixed_use_declarations const_decl inner_statement
%type <ast> expr optional_expr while_statement for_statement foreach_variable
%type <ast> foreach_statement declare_statement finally_statement unset_variable variable
%type <ast> extends_from parameter optional_type argument expr_without_variable global_var
%type <ast> static_var class_statement trait_adaptation trait_precedence trait_alias
%type <ast> absolute_trait_method_reference trait_method_reference property echo_expr
%type <ast> new_expr anonymous_class class_name class_name_reference simple_variable
%type <ast> internal_functions_in_yacc
%type <ast> exit_expr scalar backticks_expr lexical_var function_call member_name property_name
%type <ast> variable_class_name dereferencable_scalar constant dereferencable
%type <ast> callable_expr callable_variable static_member new_variable
%type <ast> encaps_var encaps_var_offset isset_variables
%type <ast> top_statement_list use_declarations const_list inner_statement_list if_stmt
%type <ast> alt_if_stmt for_exprs switch_case_list global_var_list static_var_list
%type <ast> echo_expr_list unset_variables catch_name_list catch_list parameter_list class_statement_list
%type <ast> implements_list case_list if_stmt_without_else
%type <ast> non_empty_parameter_list argument_list non_empty_argument_list property_list
%type <ast> class_const_list class_const_decl name_list trait_adaptations method_body non_empty_for_exprs
%type <ast> ctor_arguments alt_if_stmt_without_else trait_adaptation_list lexical_vars
%type <ast> lexical_var_list encaps_list
%type <ast> array_pair non_empty_array_pair_list array_pair_list possible_array_pair
%type <ast> isset_variable type return_type type_expr
%type <ast> identifier
%type <num> returns_ref function is_reference is_variadic variable_modifiers
%type <num> method_modifiers non_empty_member_modifiers member_modifier
%type <num> class_modifiers class_modifier use_type backup_fn_flags
%type <str> backup_doc_comment
%% /* Rules */
start:
	top_statement_list	{ CG(ast) = $1; }
;
reserved_non_modifiers:
	  T_INCLUDE | T_INCLUDE_ONCE | T_EVAL | T_REQUIRE | T_REQUIRE_ONCE | T_LOGICAL_OR | T_LOGICAL_XOR | T_LOGICAL_AND
	| T_INSTANCEOF | T_NEW | T_CLONE | T_EXIT | T_IF | T_ELSEIF | T_ELSE | T_ENDIF | T_ECHO | T_DO | T_WHILE | T_ENDWHILE
	| T_FOR | T_ENDFOR | T_FOREACH | T_ENDFOREACH | T_DECLARE | T_ENDDECLARE | T_AS | T_TRY | T_CATCH | T_FINALLY
	| T_THROW | T_USE | T_INSTEADOF | T_GLOBAL | T_VAR | T_UNSET | T_ISSET | T_EMPTY | T_CONTINUE | T_GOTO
	| T_FUNCTION | T_CONST | T_RETURN | T_PRINT | T_YIELD | T_LIST | T_SWITCH | T_ENDSWITCH | T_CASE | T_DEFAULT | T_BREAK
	| T_ARRAY | T_CALLABLE | T_EXTENDS | T_IMPLEMENTS | T_NAMESPACE | T_TRAIT | T_INTERFACE | T_CLASS
	| T_CLASS_C | T_TRAIT_C | T_FUNC_C | T_METHOD_C | T_LINE | T_FILE | T_DIR | T_NS_C
;
semi_reserved:
	  reserved_non_modifiers
	| T_STATIC | T_ABSTRACT | T_FINAL | T_PRIVATE | T_PROTECTED | T_PUBLIC
;
identifier:
		T_STRING { $$ = $1; }
	| 	semi_reserved  {
			zval zv;
			zend_lex_tstring(&zv);
			$$ = zend_ast_create_zval(&zv);
		}
;
top_statement_list:
		top_statement_list top_statement { $$ = zend_ast_list_add($1, $2); }
	|	/* empty */ { $$ = zend_ast_create_list(0, ZEND_AST_STMT_LIST); }
;
namespace_name:
		T_STRING								{ $$ = $1; }
	|	namespace_name T_NS_SEPARATOR T_STRING	{ $$ = zend_ast_append_str($1, $3); }
;
name:
		namespace_name								{ $$ = $1; $$->attr = ZEND_NAME_NOT_FQ; }
	|	T_NAMESPACE T_NS_SEPARATOR namespace_name	{ $$ = $3; $$->attr = ZEND_NAME_RELATIVE; }
	|	T_NS_SEPARATOR namespace_name				{ $$ = $2; $$->attr = ZEND_NAME_FQ; }
;
top_statement:
		statement							{ $$ = $1; }
	|	function_declaration_statement		{ $$ = $1; }
	|	class_declaration_statement			{ $$ = $1; }
	|	trait_declaration_statement			{ $$ = $1; }
	|	interface_declaration_statement		{ $$ = $1; }
	|	T_HALT_COMPILER '(' ')' ';'
			{ $$ = zend_ast_create(ZEND_AST_HALT_COMPILER,
			      zend_ast_create_zval_from_long(zend_get_scanned_file_offset()));
			  zend_stop_lexing(); }
	|	T_NAMESPACE namespace_name ';'
			{ $$ = zend_ast_create(ZEND_AST_NAMESPACE, $2, NULL);
			  RESET_DOC_COMMENT(); }
	|	T_NAMESPACE namespace_name { RESET_DOC_COMMENT(); }
		'{' top_statement_list '}'
			{ $$ = zend_ast_create(ZEND_AST_NAMESPACE, $2, $5); }
	|	T_NAMESPACE { RESET_DOC_COMMENT(); }
		'{' top_statement_list '}'
			{ $$ = zend_ast_create(ZEND_AST_NAMESPACE, NULL, $4); }
	|	T_USE mixed_group_use_declaration ';'		{ $$ = $2; }
	|	T_USE use_type group_use_declaration ';'	{ $$ = $3; $$->attr = $2; }
	|	T_USE use_declarations ';'					{ $$ = $2; $$->attr = ZEND_SYMBOL_CLASS; }
	|	T_USE use_type use_declarations ';'			{ $$ = $3; $$->attr = $2; }
	|	T_CONST const_list ';'						{ $$ = $2; }
;
use_type:
	 	T_FUNCTION 		{ $$ = ZEND_SYMBOL_FUNCTION; }
	| 	T_CONST 		{ $$ = ZEND_SYMBOL_CONST; }
;
group_use_declaration:
		namespace_name T_NS_SEPARATOR '{' unprefixed_use_declarations possible_comma '}'
			{ $$ = zend_ast_create(ZEND_AST_GROUP_USE, $1, $4); }
	|	T_NS_SEPARATOR namespace_name T_NS_SEPARATOR '{' unprefixed_use_declarations possible_comma '}'
			{ $$ = zend_ast_create(ZEND_AST_GROUP_USE, $2, $5); }
;
mixed_group_use_declaration:
		namespace_name T_NS_SEPARATOR '{' inline_use_declarations possible_comma '}'
			{ $$ = zend_ast_create(ZEND_AST_GROUP_USE, $1, $4);}
	|	T_NS_SEPARATOR namespace_name T_NS_SEPARATOR '{' inline_use_declarations possible_comma '}'
			{ $$ = zend_ast_create(ZEND_AST_GROUP_USE, $2, $5); }
;
possible_comma:
		/* empty */
	|	','
;
inline_use_declarations:
		inline_use_declarations ',' inline_use_declaration
			{ $$ = zend_ast_list_add($1, $3); }
	|	inline_use_declaration
			{ $$ = zend_ast_create_list(1, ZEND_AST_USE, $1); }
;
unprefixed_use_declarations:
		unprefixed_use_declarations ',' unprefixed_use_declaration
			{ $$ = zend_ast_list_add($1, $3); }
	|	unprefixed_use_declaration
			{ $$ = zend_ast_create_list(1, ZEND_AST_USE, $1); }
;
use_declarations:
		use_declarations ',' use_declaration
			{ $$ = zend_ast_list_add($1, $3); }
	|	use_declaration
			{ $$ = zend_ast_create_list(1, ZEND_AST_USE, $1); }
;
inline_use_declaration:
		unprefixed_use_declaration { $$ = $1; $$->attr = ZEND_SYMBOL_CLASS; }
	|	use_type unprefixed_use_declaration { $$ = $2; $$->attr = $1; }
;
unprefixed_use_declaration:
		namespace_name
			{ $$ = zend_ast_create(ZEND_AST_USE_ELEM, $1, NULL); }
	|	namespace_name T_AS T_STRING
			{ $$ = zend_ast_create(ZEND_AST_USE_ELEM, $1, $3); }
;
use_declaration:
		unprefixed_use_declaration                { $$ = $1; }
	|	T_NS_SEPARATOR unprefixed_use_declaration { $$ = $2; }
;
const_list:
		const_list ',' const_decl { $$ = zend_ast_list_add($1, $3); }
	|	const_decl { $$ = zend_ast_create_list(1, ZEND_AST_CONST_DECL, $1); }
;
inner_statement_list:
		inner_statement_list inner_statement
			{ $$ = zend_ast_list_add($1, $2); }
	|	/* empty */
			{ $$ = zend_ast_create_list(0, ZEND_AST_STMT_LIST); }
;
inner_statement:
		statement { $$ = $1; }
	|	function_declaration_statement 		{ $$ = $1; }
	|	class_declaration_statement 		{ $$ = $1; }
	|	trait_declaration_statement			{ $$ = $1; }
	|	interface_declaration_statement		{ $$ = $1; }
	|	T_HALT_COMPILER '(' ')' ';'
			{ $$ = NULL; zend_error_noreturn(E_COMPILE_ERROR,
			      "__HALT_COMPILER() can only be used from the outermost scope"); }
;
statement:
		'{' inner_statement_list '}' { $$ = $2; }
	|	if_stmt { $$ = $1; }
	|	alt_if_stmt { $$ = $1; }
	|	T_WHILE '(' expr ')' while_statement
			{ $$ = zend_ast_create(ZEND_AST_WHILE, $3, $5); }
	|	T_DO statement T_WHILE '(' expr ')' ';'
			{ $$ = zend_ast_create(ZEND_AST_DO_WHILE, $2, $5); }
	|	T_FOR '(' for_exprs ';' for_exprs ';' for_exprs ')' for_statement
			{ $$ = zend_ast_create(ZEND_AST_FOR, $3, $5, $7, $9); }
	|	T_SWITCH '(' expr ')' switch_case_list
			{ $$ = zend_ast_create(ZEND_AST_SWITCH, $3, $5); }
	|	T_BREAK optional_expr ';'		{ $$ = zend_ast_create(ZEND_AST_BREAK, $2); }
	|	T_CONTINUE optional_expr ';'	{ $$ = zend_ast_create(ZEND_AST_CONTINUE, $2); }
	|	T_RETURN optional_expr ';'		{ $$ = zend_ast_create(ZEND_AST_RETURN, $2); }
	|	T_GLOBAL global_var_list ';'	{ $$ = $2; }
	|	T_STATIC static_var_list ';'	{ $$ = $2; }
	|	T_ECHO echo_expr_list ';'		{ $$ = $2; }
	|	T_INLINE_HTML { $$ = zend_ast_create(ZEND_AST_ECHO, $1); }
	|	expr ';' { $$ = $1; }
	|	T_UNSET '(' unset_variables possible_comma ')' ';' { $$ = $3; }
	|	T_FOREACH '(' expr T_AS foreach_variable ')' foreach_statement
			{ $$ = zend_ast_create(ZEND_AST_FOREACH, $3, $5, NULL, $7); }
	|	T_FOREACH '(' expr T_AS foreach_variable T_DOUBLE_ARROW foreach_variable ')'
		foreach_statement
			{ $$ = zend_ast_create(ZEND_AST_FOREACH, $3, $7, $5, $9); }
	|	T_DECLARE '(' const_list ')'
			{ zend_handle_encoding_declaration($3); }
		declare_statement
			{ $$ = zend_ast_create(ZEND_AST_DECLARE, $3, $6); }
	|	';'	/* empty statement */ { $$ = NULL; }
	|	T_TRY '{' inner_statement_list '}' catch_list finally_statement
			{ $$ = zend_ast_create(ZEND_AST_TRY, $3, $5, $6); }
	|	T_THROW expr ';' { $$ = zend_ast_create(ZEND_AST_THROW, $2); }
	|	T_GOTO T_STRING ';' { $$ = zend_ast_create(ZEND_AST_GOTO, $2); }
	|	T_STRING ':' { $$ = zend_ast_create(ZEND_AST_LABEL, $1); }
;
catch_list:
		/* empty */
			{ $$ = zend_ast_create_list(0, ZEND_AST_CATCH_LIST); }
	|	catch_list T_CATCH '(' catch_name_list T_VARIABLE ')' '{' inner_statement_list '}'
			{ $$ = zend_ast_list_add($1, zend_ast_create(ZEND_AST_CATCH, $4, $5, $8)); }
;
catch_name_list:
		name { $$ = zend_ast_create_list(1, ZEND_AST_NAME_LIST, $1); }
	|	catch_name_list '|' name { $$ = zend_ast_list_add($1, $3); }
;
finally_statement:
		/* empty */ { $$ = NULL; }
	|	T_FINALLY '{' inner_statement_list '}' { $$ = $3; }
;
unset_variables:
		unset_variable { $$ = zend_ast_create_list(1, ZEND_AST_STMT_LIST, $1); }
	|	unset_variables ',' unset_variable { $$ = zend_ast_list_add($1, $3); }
;
unset_variable:
		variable { $$ = zend_ast_create(ZEND_AST_UNSET, $1); }
;
function_declaration_statement:
	function returns_ref T_STRING backup_doc_comment '(' parameter_list ')' return_type
	backup_fn_flags '{' inner_statement_list '}' backup_fn_flags
		{ $$ = zend_ast_create_decl(ZEND_AST_FUNC_DECL, $2 | $13, $1, $4,
		      zend_ast_get_str($3), $6, NULL, $11, $8); CG(extra_fn_flags) = $9; }
;
is_reference:
		/* empty */	{ $$ = 0; }
	|	'&'			{ $$ = ZEND_PARAM_REF; }
;
is_variadic:
		/* empty */ { $$ = 0; }
	|	T_ELLIPSIS  { $$ = ZEND_PARAM_VARIADIC; }
;
class_declaration_statement:
		class_modifiers T_CLASS { $<num>$ = CG(zend_lineno); }
		T_STRING extends_from implements_list backup_doc_comment '{' class_statement_list '}'
			{ $$ = zend_ast_create_decl(ZEND_AST_CLASS, $1, $<num>3, $7, zend_ast_get_str($4), $5, $6, $9, NULL); }
	|	T_CLASS { $<num>$ = CG(zend_lineno); }
		T_STRING extends_from implements_list backup_doc_comment '{' class_statement_list '}'
			{ $$ = zend_ast_create_decl(ZEND_AST_CLASS, 0, $<num>2, $6, zend_ast_get_str($3), $4, $5, $8, NULL); }
;
class_modifiers:
		class_modifier 					{ $$ = $1; }
	|	class_modifiers class_modifier 	{ $$ = zend_add_class_modifier($1, $2); }
;
class_modifier:
		T_ABSTRACT 		{ $$ = ZEND_ACC_EXPLICIT_ABSTRACT_CLASS; }
	|	T_FINAL 		{ $$ = ZEND_ACC_FINAL; }
;
trait_declaration_statement:
		T_TRAIT { $<num>$ = CG(zend_lineno); }
		T_STRING backup_doc_comment '{' class_statement_list '}'
			{ $$ = zend_ast_create_decl(ZEND_AST_CLASS, ZEND_ACC_TRAIT, $<num>2, $4, zend_ast_get_str($3), NULL, NULL, $6, NULL); }
;
interface_declaration_statement:
		T_INTERFACE { $<num>$ = CG(zend_lineno); }
		T_STRING interface_extends_list backup_doc_comment '{' class_statement_list '}'
			{ $$ = zend_ast_create_decl(ZEND_AST_CLASS, ZEND_ACC_INTERFACE, $<num>2, $5, zend_ast_get_str($3), NULL, $4, $7, NULL); }
;
extends_from:
		/* empty */		{ $$ = NULL; }
	|	T_EXTENDS name	{ $$ = $2; }
;
interface_extends_list:
		/* empty */			{ $$ = NULL; }
	|	T_EXTENDS name_list	{ $$ = $2; }
;
implements_list:
		/* empty */				{ $$ = NULL; }
	|	T_IMPLEMENTS name_list	{ $$ = $2; }
;
foreach_variable:
		variable			{ $$ = $1; }
	|	'&' variable		{ $$ = zend_ast_create(ZEND_AST_REF, $2); }
	|	T_LIST '(' array_pair_list ')' { $$ = $3; $$->attr = ZEND_ARRAY_SYNTAX_LIST; }
	|	'[' array_pair_list ']' { $$ = $2; $$->attr = ZEND_ARRAY_SYNTAX_SHORT; }
;
for_statement:
		statement { $$ = $1; }
	|	':' inner_statement_list T_ENDFOR ';' { $$ = $2; }
;
foreach_statement:
		statement { $$ = $1; }
	|	':' inner_statement_list T_ENDFOREACH ';' { $$ = $2; }
;
declare_statement:
		statement { $$ = $1; }
	|	':' inner_statement_list T_ENDDECLARE ';' { $$ = $2; }
;
switch_case_list:
		'{' case_list '}'					{ $$ = $2; }
	|	'{' ';' case_list '}'				{ $$ = $3; }
	|	':' case_list T_ENDSWITCH ';'		{ $$ = $2; }
	|	':' ';' case_list T_ENDSWITCH ';'	{ $$ = $3; }
;
case_list:
		/* empty */ { $$ = zend_ast_create_list(0, ZEND_AST_SWITCH_LIST); }
	|	case_list T_CASE expr case_separator inner_statement_list
			{ $$ = zend_ast_list_add($1, zend_ast_create(ZEND_AST_SWITCH_CASE, $3, $5)); }
	|	case_list T_DEFAULT case_separator inner_statement_list
			{ $$ = zend_ast_list_add($1, zend_ast_create(ZEND_AST_SWITCH_CASE, NULL, $4)); }
;
case_separator:
		':'
	|	';'
;
while_statement:
		statement { $$ = $1; }
	|	':' inner_statement_list T_ENDWHILE ';' { $$ = $2; }
;
if_stmt_without_else:
		T_IF '(' expr ')' statement
			{ $$ = zend_ast_create_list(1, ZEND_AST_IF,
			      zend_ast_create(ZEND_AST_IF_ELEM, $3, $5)); }
	|	if_stmt_without_else T_ELSEIF '(' expr ')' statement
			{ $$ = zend_ast_list_add($1,
			      zend_ast_create(ZEND_AST_IF_ELEM, $4, $6)); }
;
if_stmt:
		if_stmt_without_else %prec T_NOELSE { $$ = $1; }
	|	if_stmt_without_else T_ELSE statement
			{ $$ = zend_ast_list_add($1, zend_ast_create(ZEND_AST_IF_ELEM, NULL, $3)); }
;
alt_if_stmt_without_else:
		T_IF '(' expr ')' ':' inner_statement_list
			{ $$ = zend_ast_create_list(1, ZEND_AST_IF,
			      zend_ast_create(ZEND_AST_IF_ELEM, $3, $6)); }
	|	alt_if_stmt_without_else T_ELSEIF '(' expr ')' ':' inner_statement_list
			{ $$ = zend_ast_list_add($1,
			      zend_ast_create(ZEND_AST_IF_ELEM, $4, $7)); }
;
alt_if_stmt:
		alt_if_stmt_without_else T_ENDIF ';' { $$ = $1; }
	|	alt_if_stmt_without_else T_ELSE ':' inner_statement_list T_ENDIF ';'
			{ $$ = zend_ast_list_add($1,
			      zend_ast_create(ZEND_AST_IF_ELEM, NULL, $4)); }
;
parameter_list:
		non_empty_parameter_list { $$ = $1; }
	|	/* empty */	{ $$ = zend_ast_create_list(0, ZEND_AST_PARAM_LIST); }
;
non_empty_parameter_list:
		parameter
			{ $$ = zend_ast_create_list(1, ZEND_AST_PARAM_LIST, $1); }
	|	non_empty_parameter_list ',' parameter
			{ $$ = zend_ast_list_add($1, $3); }
;
parameter:
		optional_type is_reference is_variadic T_VARIABLE
			{ $$ = zend_ast_create_ex(ZEND_AST_PARAM, $2 | $3, $1, $4, NULL); }
	|	optional_type is_reference is_variadic T_VARIABLE '=' expr
			{ $$ = zend_ast_create_ex(ZEND_AST_PARAM, $2 | $3, $1, $4, $6); }
;
optional_type:
		/* empty */	{ $$ = NULL; }
	|	type_expr	{ $$ = $1; }
;
type_expr:
		type		{ $$ = $1; }
	|	'?' type	{ $$ = $2; $$->attr |= ZEND_TYPE_NULLABLE; }
;
type:
		T_ARRAY		{ $$ = zend_ast_create_ex(ZEND_AST_TYPE, IS_ARRAY); }
	|	T_CALLABLE	{ $$ = zend_ast_create_ex(ZEND_AST_TYPE, IS_CALLABLE); }
	|	name		{ $$ = $1; }
;
return_type:
		/* empty */	{ $$ = NULL; }
	|	':' type_expr	{ $$ = $2; }
;
argument_list:
		'(' ')'	{ $$ = zend_ast_create_list(0, ZEND_AST_ARG_LIST); }
	|	'(' non_empty_argument_list possible_comma ')' { $$ = $2; }
;
non_empty_argument_list:
		argument
			{ $$ = zend_ast_create_list(1, ZEND_AST_ARG_LIST, $1); }
	|	non_empty_argument_list ',' argument
			{ $$ = zend_ast_list_add($1, $3); }
;
argument:
		expr			{ $$ = $1; }
	|	T_ELLIPSIS expr	{ $$ = zend_ast_create(ZEND_AST_UNPACK, $2); }
;
global_var_list:
		global_var_list ',' global_var { $$ = zend_ast_list_add($1, $3); }
	|	global_var { $$ = zend_ast_create_list(1, ZEND_AST_STMT_LIST, $1); }
;
global_var:
	simple_variable
		{ $$ = zend_ast_create(ZEND_AST_GLOBAL, zend_ast_create(ZEND_AST_VAR, $1)); }
;
static_var_list:
		static_var_list ',' static_var { $$ = zend_ast_list_add($1, $3); }
	|	static_var { $$ = zend_ast_create_list(1, ZEND_AST_STMT_LIST, $1); }
;
static_var:
		T_VARIABLE			{ $$ = zend_ast_create(ZEND_AST_STATIC, $1, NULL); }
	|	T_VARIABLE '=' expr	{ $$ = zend_ast_create(ZEND_AST_STATIC, $1, $3); }
;
class_statement_list:
		class_statement_list class_statement
			{ $$ = zend_ast_list_add($1, $2); }
	|	/* empty */
			{ $$ = zend_ast_create_list(0, ZEND_AST_STMT_LIST); }
;
class_statement:
		variable_modifiers property_list ';'
			{ $$ = $2; $$->attr = $1; }
	|	method_modifiers T_CONST class_const_list ';'
			{ $$ = $3; $$->attr = $1; }
	|	T_USE name_list trait_adaptations
			{ $$ = zend_ast_create(ZEND_AST_USE_TRAIT, $2, $3); }
	|	method_modifiers function returns_ref identifier backup_doc_comment '(' parameter_list ')'
		return_type backup_fn_flags method_body backup_fn_flags
			{ $$ = zend_ast_create_decl(ZEND_AST_METHOD, $3 | $1 | $12, $2, $5,
				  zend_ast_get_str($4), $7, NULL, $11, $9); CG(extra_fn_flags) = $10; }
;
name_list:
		name { $$ = zend_ast_create_list(1, ZEND_AST_NAME_LIST, $1); }
	|	name_list ',' name { $$ = zend_ast_list_add($1, $3); }
;
trait_adaptations:
		';'								{ $$ = NULL; }
	|	'{' '}'							{ $$ = NULL; }
	|	'{' trait_adaptation_list '}'	{ $$ = $2; }
;
trait_adaptation_list:
		trait_adaptation
			{ $$ = zend_ast_create_list(1, ZEND_AST_TRAIT_ADAPTATIONS, $1); }
	|	trait_adaptation_list trait_adaptation
			{ $$ = zend_ast_list_add($1, $2); }
;
trait_adaptation:
		trait_precedence ';'	{ $$ = $1; }
	|	trait_alias ';'			{ $$ = $1; }
;
trait_precedence:
	absolute_trait_method_reference T_INSTEADOF name_list
		{ $$ = zend_ast_create(ZEND_AST_TRAIT_PRECEDENCE, $1, $3); }
;
trait_alias:
		trait_method_reference T_AS T_STRING
			{ $$ = zend_ast_create(ZEND_AST_TRAIT_ALIAS, $1, $3); }
	|	trait_method_reference T_AS reserved_non_modifiers
			{ zval zv; zend_lex_tstring(&zv); $$ = zend_ast_create(ZEND_AST_TRAIT_ALIAS, $1, zend_ast_create_zval(&zv)); }
	|	trait_method_reference T_AS member_modifier identifier
			{ $$ = zend_ast_create_ex(ZEND_AST_TRAIT_ALIAS, $3, $1, $4); }
	|	trait_method_reference T_AS member_modifier
			{ $$ = zend_ast_create_ex(ZEND_AST_TRAIT_ALIAS, $3, $1, NULL); }
;
trait_method_reference:
		identifier
			{ $$ = zend_ast_create(ZEND_AST_METHOD_REFERENCE, NULL, $1); }
	|	absolute_trait_method_reference { $$ = $1; }
;
absolute_trait_method_reference:
	name T_PAAMAYIM_NEKUDOTAYIM identifier
		{ $$ = zend_ast_create(ZEND_AST_METHOD_REFERENCE, $1, $3); }
;
method_body:
		';' /* abstract method */		{ $$ = NULL; }
	|	'{' inner_statement_list '}'	{ $$ = $2; }
;
variable_modifiers:
		non_empty_member_modifiers		{ $$ = $1; }
	|	T_VAR							{ $$ = ZEND_ACC_PUBLIC; }
;
method_modifiers:
		/* empty */						{ $$ = ZEND_ACC_PUBLIC; }
	|	non_empty_member_modifiers
			{ $$ = $1; if (!($$ & ZEND_ACC_PPP_MASK)) { $$ |= ZEND_ACC_PUBLIC; } }
;
non_empty_member_modifiers:
		member_modifier			{ $$ = $1; }
	|	non_empty_member_modifiers member_modifier
			{ $$ = zend_add_member_modifier($1, $2); }
;
member_modifier:
		T_PUBLIC				{ $$ = ZEND_ACC_PUBLIC; }
	|	T_PROTECTED				{ $$ = ZEND_ACC_PROTECTED; }
	|	T_PRIVATE				{ $$ = ZEND_ACC_PRIVATE; }
	|	T_STATIC				{ $$ = ZEND_ACC_STATIC; }
	|	T_ABSTRACT				{ $$ = ZEND_ACC_ABSTRACT; }
	|	T_FINAL					{ $$ = ZEND_ACC_FINAL; }
;
property_list:
		property_list ',' property { $$ = zend_ast_list_add($1, $3); }
	|	property { $$ = zend_ast_create_list(1, ZEND_AST_PROP_DECL, $1); }
;
property:
		T_VARIABLE backup_doc_comment
			{ $$ = zend_ast_create(ZEND_AST_PROP_ELEM, $1, NULL, ($2 ? zend_ast_create_zval_from_str($2) : NULL)); }
	|	T_VARIABLE '=' expr backup_doc_comment
			{ $$ = zend_ast_create(ZEND_AST_PROP_ELEM, $1, $3, ($4 ? zend_ast_create_zval_from_str($4) : NULL)); }
;
class_const_list:
		class_const_list ',' class_const_decl { $$ = zend_ast_list_add($1, $3); }
	|	class_const_decl { $$ = zend_ast_create_list(1, ZEND_AST_CLASS_CONST_DECL, $1); }
;
class_const_decl:
	identifier '=' expr backup_doc_comment { $$ = zend_ast_create(ZEND_AST_CONST_ELEM, $1, $3, ($4 ? zend_ast_create_zval_from_str($4) : NULL)); }
;
const_decl:
	T_STRING '=' expr backup_doc_comment { $$ = zend_ast_create(ZEND_AST_CONST_ELEM, $1, $3, ($4 ? zend_ast_create_zval_from_str($4) : NULL)); }
;
echo_expr_list:
		echo_expr_list ',' echo_expr { $$ = zend_ast_list_add($1, $3); }
	|	echo_expr { $$ = zend_ast_create_list(1, ZEND_AST_STMT_LIST, $1); }
;
echo_expr:
	expr { $$ = zend_ast_create(ZEND_AST_ECHO, $1); }
;
for_exprs:
		/* empty */			{ $$ = NULL; }
	|	non_empty_for_exprs	{ $$ = $1; }
;
non_empty_for_exprs:
		non_empty_for_exprs ',' expr { $$ = zend_ast_list_add($1, $3); }
	|	expr { $$ = zend_ast_create_list(1, ZEND_AST_EXPR_LIST, $1); }
;
anonymous_class:
        T_CLASS { $<num>$ = CG(zend_lineno); } ctor_arguments
		extends_from implements_list backup_doc_comment '{' class_statement_list '}' {
			zend_ast *decl = zend_ast_create_decl(
				ZEND_AST_CLASS, ZEND_ACC_ANON_CLASS, $<num>2, $6, NULL,
				$4, $5, $8, NULL);
			$$ = zend_ast_create(ZEND_AST_NEW, decl, $3);
		}
;
new_expr:
		T_NEW class_name_reference ctor_arguments
			{ $$ = zend_ast_create(ZEND_AST_NEW, $2, $3); }
	|	T_NEW anonymous_class
			{ $$ = $2; }
;
expr_without_variable:
		T_LIST '(' array_pair_list ')' '=' expr
			{ $3->attr = ZEND_ARRAY_SYNTAX_LIST; $$ = zend_ast_create(ZEND_AST_ASSIGN, $3, $6); }
	|	'[' array_pair_list ']' '=' expr
			{ $2->attr = ZEND_ARRAY_SYNTAX_SHORT; $$ = zend_ast_create(ZEND_AST_ASSIGN, $2, $5); }
	|	variable '=' expr
			{ $$ = zend_ast_create(ZEND_AST_ASSIGN, $1, $3); }
	|	variable '=' '&' variable
			{ $$ = zend_ast_create(ZEND_AST_ASSIGN_REF, $1, $4); }
	|	T_CLONE expr { $$ = zend_ast_create(ZEND_AST_CLONE, $2); }
	|	variable T_PLUS_EQUAL expr
			{ $$ = zend_ast_create_assign_op(ZEND_ASSIGN_ADD, $1, $3); }
	|	variable T_MINUS_EQUAL expr
			{ $$ = zend_ast_create_assign_op(ZEND_ASSIGN_SUB, $1, $3); }
	|	variable T_MUL_EQUAL expr
			{ $$ = zend_ast_create_assign_op(ZEND_ASSIGN_MUL, $1, $3); }
	|	variable T_POW_EQUAL expr
			{ $$ = zend_ast_create_assign_op(ZEND_ASSIGN_POW, $1, $3); }
	|	variable T_DIV_EQUAL expr
			{ $$ = zend_ast_create_assign_op(ZEND_ASSIGN_DIV, $1, $3); }
	|	variable T_CONCAT_EQUAL expr
			{ $$ = zend_ast_create_assign_op(ZEND_ASSIGN_CONCAT, $1, $3); }
	|	variable T_MOD_EQUAL expr
			{ $$ = zend_ast_create_assign_op(ZEND_ASSIGN_MOD, $1, $3); }
	|	variable T_AND_EQUAL expr
			{ $$ = zend_ast_create_assign_op(ZEND_ASSIGN_BW_AND, $1, $3); }
	|	variable T_OR_EQUAL expr
			{ $$ = zend_ast_create_assign_op(ZEND_ASSIGN_BW_OR, $1, $3); }
	|	variable T_XOR_EQUAL expr
			{ $$ = zend_ast_create_assign_op(ZEND_ASSIGN_BW_XOR, $1, $3); }
	|	variable T_SL_EQUAL expr
			{ $$ = zend_ast_create_assign_op(ZEND_ASSIGN_SL, $1, $3); }
	|	variable T_SR_EQUAL expr
			{ $$ = zend_ast_create_assign_op(ZEND_ASSIGN_SR, $1, $3); }
	|	variable T_INC { $$ = zend_ast_create(ZEND_AST_POST_INC, $1); }
	|	T_INC variable { $$ = zend_ast_create(ZEND_AST_PRE_INC, $2); }
	|	variable T_DEC { $$ = zend_ast_create(ZEND_AST_POST_DEC, $1); }
	|	T_DEC variable { $$ = zend_ast_create(ZEND_AST_PRE_DEC, $2); }
	|	expr T_BOOLEAN_OR expr
			{ $$ = zend_ast_create(ZEND_AST_OR, $1, $3); }
	|	expr T_BOOLEAN_AND expr
			{ $$ = zend_ast_create(ZEND_AST_AND, $1, $3); }
	|	expr T_LOGICAL_OR expr
			{ $$ = zend_ast_create(ZEND_AST_OR, $1, $3); }
	|	expr T_LOGICAL_AND expr
			{ $$ = zend_ast_create(ZEND_AST_AND, $1, $3); }
	|	expr T_LOGICAL_XOR expr
			{ $$ = zend_ast_create_binary_op(ZEND_BOOL_XOR, $1, $3); }
	|	expr '|' expr	{ $$ = zend_ast_create_binary_op(ZEND_BW_OR, $1, $3); }
	|	expr '&' expr	{ $$ = zend_ast_create_binary_op(ZEND_BW_AND, $1, $3); }
	|	expr '^' expr	{ $$ = zend_ast_create_binary_op(ZEND_BW_XOR, $1, $3); }
	|	expr '.' expr 	{ $$ = zend_ast_create_binary_op(ZEND_CONCAT, $1, $3); }
	|	expr '+' expr 	{ $$ = zend_ast_create_binary_op(ZEND_ADD, $1, $3); }
	|	expr '-' expr 	{ $$ = zend_ast_create_binary_op(ZEND_SUB, $1, $3); }
	|	expr '*' expr	{ $$ = zend_ast_create_binary_op(ZEND_MUL, $1, $3); }
	|	expr T_POW expr	{ $$ = zend_ast_create_binary_op(ZEND_POW, $1, $3); }
	|	expr '/' expr	{ $$ = zend_ast_create_binary_op(ZEND_DIV, $1, $3); }
	|	expr '%' expr 	{ $$ = zend_ast_create_binary_op(ZEND_MOD, $1, $3); }
	| 	expr T_SL expr	{ $$ = zend_ast_create_binary_op(ZEND_SL, $1, $3); }
	|	expr T_SR expr	{ $$ = zend_ast_create_binary_op(ZEND_SR, $1, $3); }
	|	'+' expr %prec T_INC { $$ = zend_ast_create(ZEND_AST_UNARY_PLUS, $2); }
	|	'-' expr %prec T_INC { $$ = zend_ast_create(ZEND_AST_UNARY_MINUS, $2); }
	|	'!' expr { $$ = zend_ast_create_ex(ZEND_AST_UNARY_OP, ZEND_BOOL_NOT, $2); }
	|	'~' expr { $$ = zend_ast_create_ex(ZEND_AST_UNARY_OP, ZEND_BW_NOT, $2); }
	|	expr T_IS_IDENTICAL expr
			{ $$ = zend_ast_create_binary_op(ZEND_IS_IDENTICAL, $1, $3); }
	|	expr T_IS_NOT_IDENTICAL expr
			{ $$ = zend_ast_create_binary_op(ZEND_IS_NOT_IDENTICAL, $1, $3); }
	|	expr T_IS_EQUAL expr
			{ $$ = zend_ast_create_binary_op(ZEND_IS_EQUAL, $1, $3); }
	|	expr T_IS_NOT_EQUAL expr
			{ $$ = zend_ast_create_binary_op(ZEND_IS_NOT_EQUAL, $1, $3); }
	|	expr '<' expr
			{ $$ = zend_ast_create_binary_op(ZEND_IS_SMALLER, $1, $3); }
	|	expr T_IS_SMALLER_OR_EQUAL expr
			{ $$ = zend_ast_create_binary_op(ZEND_IS_SMALLER_OR_EQUAL, $1, $3); }
	|	expr '>' expr
			{ $$ = zend_ast_create(ZEND_AST_GREATER, $1, $3); }
	|	expr T_IS_GREATER_OR_EQUAL expr
			{ $$ = zend_ast_create(ZEND_AST_GREATER_EQUAL, $1, $3); }
	|	expr T_SPACESHIP expr
			{ $$ = zend_ast_create_binary_op(ZEND_SPACESHIP, $1, $3); }
	|	expr T_INSTANCEOF class_name_reference
			{ $$ = zend_ast_create(ZEND_AST_INSTANCEOF, $1, $3); }
	|	'(' expr ')' { $$ = $2; }
	|	new_expr { $$ = $1; }
	|	expr '?' expr ':' expr
			{ $$ = zend_ast_create(ZEND_AST_CONDITIONAL, $1, $3, $5); }
	|	expr '?' ':' expr
			{ $$ = zend_ast_create(ZEND_AST_CONDITIONAL, $1, NULL, $4); }
	|	expr T_COALESCE expr
			{ $$ = zend_ast_create(ZEND_AST_COALESCE, $1, $3); }
	|	internal_functions_in_yacc { $$ = $1; }
	|	T_INT_CAST expr		{ $$ = zend_ast_create_cast(IS_LONG, $2); }
	|	T_DOUBLE_CAST expr	{ $$ = zend_ast_create_cast(IS_DOUBLE, $2); }
	|	T_STRING_CAST expr	{ $$ = zend_ast_create_cast(IS_STRING, $2); }
	|	T_ARRAY_CAST expr	{ $$ = zend_ast_create_cast(IS_ARRAY, $2); }
	|	T_OBJECT_CAST expr	{ $$ = zend_ast_create_cast(IS_OBJECT, $2); }
	|	T_BOOL_CAST expr	{ $$ = zend_ast_create_cast(_IS_BOOL, $2); }
	|	T_UNSET_CAST expr	{ $$ = zend_ast_create_cast(IS_NULL, $2); }
	|	T_EXIT exit_expr	{ $$ = zend_ast_create(ZEND_AST_EXIT, $2); }
	|	'@' expr			{ $$ = zend_ast_create(ZEND_AST_SILENCE, $2); }
	|	scalar { $$ = $1; }
	|	'`' backticks_expr '`' { $$ = zend_ast_create(ZEND_AST_SHELL_EXEC, $2); }
	|	T_PRINT expr { $$ = zend_ast_create(ZEND_AST_PRINT, $2); }
	|	T_YIELD { $$ = zend_ast_create(ZEND_AST_YIELD, NULL, NULL); CG(extra_fn_flags) |= ZEND_ACC_GENERATOR; }
	|	T_YIELD expr { $$ = zend_ast_create(ZEND_AST_YIELD, $2, NULL); CG(extra_fn_flags) |= ZEND_ACC_GENERATOR; }
	|	T_YIELD expr T_DOUBLE_ARROW expr { $$ = zend_ast_create(ZEND_AST_YIELD, $4, $2); CG(extra_fn_flags) |= ZEND_ACC_GENERATOR; }
	|	T_YIELD_FROM expr { $$ = zend_ast_create(ZEND_AST_YIELD_FROM, $2); CG(extra_fn_flags) |= ZEND_ACC_GENERATOR; }
	|	function returns_ref backup_doc_comment '(' parameter_list ')' lexical_vars return_type
		backup_fn_flags '{' inner_statement_list '}' backup_fn_flags
			{ $$ = zend_ast_create_decl(ZEND_AST_CLOSURE, $2 | $13, $1, $3,
				  zend_string_init("{closure}", sizeof("{closure}") - 1, 0),
			      $5, $7, $11, $8); CG(extra_fn_flags) = $9; }
	|	T_STATIC function returns_ref backup_doc_comment '(' parameter_list ')' lexical_vars
		return_type backup_fn_flags '{' inner_statement_list '}' backup_fn_flags
			{ $$ = zend_ast_create_decl(ZEND_AST_CLOSURE, $3 | $14 | ZEND_ACC_STATIC, $2, $4,
			      zend_string_init("{closure}", sizeof("{closure}") - 1, 0),
			      $6, $8, $12, $9); CG(extra_fn_flags) = $10; }
;
function:
	T_FUNCTION { $$ = CG(zend_lineno); }
;
backup_doc_comment:
	/* empty */ { $$ = CG(doc_comment); CG(doc_comment) = NULL; }
;
backup_fn_flags:
	/* empty */ { $$ = CG(extra_fn_flags); CG(extra_fn_flags) = 0; }
;
returns_ref:
		/* empty */	{ $$ = 0; }
	|	'&'			{ $$ = ZEND_ACC_RETURN_REFERENCE; }
;
lexical_vars:
		/* empty */ { $$ = NULL; }
	|	T_USE '(' lexical_var_list ')' { $$ = $3; }
;
lexical_var_list:
		lexical_var_list ',' lexical_var { $$ = zend_ast_list_add($1, $3); }
	|	lexical_var { $$ = zend_ast_create_list(1, ZEND_AST_CLOSURE_USES, $1); }
;
lexical_var:
		T_VARIABLE		{ $$ = $1; }
	|	'&' T_VARIABLE	{ $$ = $2; $$->attr = 1; }
;
function_call:
		name argument_list
			{ $$ = zend_ast_create(ZEND_AST_CALL, $1, $2); }
	|	class_name T_PAAMAYIM_NEKUDOTAYIM member_name argument_list
			{ $$ = zend_ast_create(ZEND_AST_STATIC_CALL, $1, $3, $4); }
	|	variable_class_name T_PAAMAYIM_NEKUDOTAYIM member_name argument_list
			{ $$ = zend_ast_create(ZEND_AST_STATIC_CALL, $1, $3, $4); }
	|	callable_expr argument_list
			{ $$ = zend_ast_create(ZEND_AST_CALL, $1, $2); }
;
class_name:
		T_STATIC
			{ zval zv; ZVAL_INTERNED_STR(&zv, ZSTR_KNOWN(ZEND_STR_STATIC));
			  $$ = zend_ast_create_zval_ex(&zv, ZEND_NAME_NOT_FQ); }
	|	name { $$ = $1; }
;
class_name_reference:
		class_name		{ $$ = $1; }
	|	new_variable	{ $$ = $1; }
;
exit_expr:
		/* empty */				{ $$ = NULL; }
	|	'(' optional_expr ')'	{ $$ = $2; }
;
backticks_expr:
		/* empty */
			{ $$ = zend_ast_create_zval_from_str(ZSTR_EMPTY_ALLOC()); }
	|	T_ENCAPSED_AND_WHITESPACE { $$ = $1; }
	|	encaps_list { $$ = $1; }
;
ctor_arguments:
		/* empty */	{ $$ = zend_ast_create_list(0, ZEND_AST_ARG_LIST); }
	|	argument_list { $$ = $1; }
;
dereferencable_scalar:
		T_ARRAY '(' array_pair_list ')'	{ $$ = $3; $$->attr = ZEND_ARRAY_SYNTAX_LONG; }
	|	'[' array_pair_list ']'			{ $$ = $2; $$->attr = ZEND_ARRAY_SYNTAX_SHORT; }
	|	T_CONSTANT_ENCAPSED_STRING		{ $$ = $1; }
;
scalar:
		T_LNUMBER 	{ $$ = $1; }
	|	T_DNUMBER 	{ $$ = $1; }
	|	T_LINE 		{ $$ = zend_ast_create_ex(ZEND_AST_MAGIC_CONST, T_LINE); }
	|	T_FILE 		{ $$ = zend_ast_create_ex(ZEND_AST_MAGIC_CONST, T_FILE); }
	|	T_DIR   	{ $$ = zend_ast_create_ex(ZEND_AST_MAGIC_CONST, T_DIR); }
	|	T_TRAIT_C	{ $$ = zend_ast_create_ex(ZEND_AST_MAGIC_CONST, T_TRAIT_C); }
	|	T_METHOD_C	{ $$ = zend_ast_create_ex(ZEND_AST_MAGIC_CONST, T_METHOD_C); }
	|	T_FUNC_C	{ $$ = zend_ast_create_ex(ZEND_AST_MAGIC_CONST, T_FUNC_C); }
	|	T_NS_C		{ $$ = zend_ast_create_ex(ZEND_AST_MAGIC_CONST, T_NS_C); }
	|	T_CLASS_C	{ $$ = zend_ast_create_ex(ZEND_AST_MAGIC_CONST, T_CLASS_C); }
	|	T_START_HEREDOC T_ENCAPSED_AND_WHITESPACE T_END_HEREDOC { $$ = $2; }
	|	T_START_HEREDOC T_END_HEREDOC
			{ $$ = zend_ast_create_zval_from_str(ZSTR_EMPTY_ALLOC()); }
	|	'"' encaps_list '"' 	{ $$ = $2; }
	|	T_START_HEREDOC encaps_list T_END_HEREDOC { $$ = $2; }
	|	dereferencable_scalar	{ $$ = $1; }
	|	constant			{ $$ = $1; }
;
constant:
		name { $$ = zend_ast_create(ZEND_AST_CONST, $1); }
	|	class_name T_PAAMAYIM_NEKUDOTAYIM identifier
			{ $$ = zend_ast_create(ZEND_AST_CLASS_CONST, $1, $3); }
	|	variable_class_name T_PAAMAYIM_NEKUDOTAYIM identifier
			{ $$ = zend_ast_create(ZEND_AST_CLASS_CONST, $1, $3); }
;
expr:
		variable					{ $$ = $1; }
	|	expr_without_variable		{ $$ = $1; }
;
optional_expr:
		/* empty */	{ $$ = NULL; }
	|	expr		{ $$ = $1; }
;
variable_class_name:
	dereferencable { $$ = $1; }
;
dereferencable:
		variable				{ $$ = $1; }
	|	'(' expr ')'			{ $$ = $2; }
	|	dereferencable_scalar	{ $$ = $1; }
;
callable_expr:
		callable_variable		{ $$ = $1; }
	|	'(' expr ')'			{ $$ = $2; }
	|	dereferencable_scalar	{ $$ = $1; }
;
callable_variable:
		simple_variable
			{ $$ = zend_ast_create(ZEND_AST_VAR, $1); }
	|	dereferencable '[' optional_expr ']'
			{ $$ = zend_ast_create(ZEND_AST_DIM, $1, $3); }
	|	constant '[' optional_expr ']'
			{ $$ = zend_ast_create(ZEND_AST_DIM, $1, $3); }
	|	dereferencable '{' expr '}'
			{ $$ = zend_ast_create(ZEND_AST_DIM, $1, $3); }
	|	dereferencable T_OBJECT_OPERATOR property_name argument_list
			{ $$ = zend_ast_create(ZEND_AST_METHOD_CALL, $1, $3, $4); }
	|	function_call { $$ = $1; }
;
variable:
		callable_variable
			{ $$ = $1; }
	|	static_member
			{ $$ = $1; }
	|	dereferencable T_OBJECT_OPERATOR property_name
			{ $$ = zend_ast_create(ZEND_AST_PROP, $1, $3); }
;
simple_variable:
		T_VARIABLE			{ $$ = $1; }
	|	'$' '{' expr '}'	{ $$ = $3; }
	|	'$' simple_variable	{ $$ = zend_ast_create(ZEND_AST_VAR, $2); }
;
static_member:
		class_name T_PAAMAYIM_NEKUDOTAYIM simple_variable
			{ $$ = zend_ast_create(ZEND_AST_STATIC_PROP, $1, $3); }
	|	variable_class_name T_PAAMAYIM_NEKUDOTAYIM simple_variable
			{ $$ = zend_ast_create(ZEND_AST_STATIC_PROP, $1, $3); }
;
new_variable:
		simple_variable
			{ $$ = zend_ast_create(ZEND_AST_VAR, $1); }
	|	new_variable '[' optional_expr ']'
			{ $$ = zend_ast_create(ZEND_AST_DIM, $1, $3); }
	|	new_variable '{' expr '}'
			{ $$ = zend_ast_create(ZEND_AST_DIM, $1, $3); }
	|	new_variable T_OBJECT_OPERATOR property_name
			{ $$ = zend_ast_create(ZEND_AST_PROP, $1, $3); }
	|	class_name T_PAAMAYIM_NEKUDOTAYIM simple_variable
			{ $$ = zend_ast_create(ZEND_AST_STATIC_PROP, $1, $3); }
	|	new_variable T_PAAMAYIM_NEKUDOTAYIM simple_variable
			{ $$ = zend_ast_create(ZEND_AST_STATIC_PROP, $1, $3); }
;
member_name:
		identifier { $$ = $1; }
	|	'{' expr '}'	{ $$ = $2; }
	|	simple_variable	{ $$ = zend_ast_create(ZEND_AST_VAR, $1); }
;
property_name:
		T_STRING { $$ = $1; }
	|	'{' expr '}'	{ $$ = $2; }
	|	simple_variable	{ $$ = zend_ast_create(ZEND_AST_VAR, $1); }
;
array_pair_list:
		non_empty_array_pair_list
			{ /* allow single trailing comma */ $$ = zend_ast_list_rtrim($1); }
;
possible_array_pair:
		/* empty */ { $$ = NULL; }
	|	array_pair  { $$ = $1; }
;
non_empty_array_pair_list:
		non_empty_array_pair_list ',' possible_array_pair
			{ $$ = zend_ast_list_add($1, $3); }
	|	possible_array_pair
			{ $$ = zend_ast_create_list(1, ZEND_AST_ARRAY, $1); }
;
array_pair:
		expr T_DOUBLE_ARROW expr
			{ $$ = zend_ast_create(ZEND_AST_ARRAY_ELEM, $3, $1); }
	|	expr
			{ $$ = zend_ast_create(ZEND_AST_ARRAY_ELEM, $1, NULL); }
	|	expr T_DOUBLE_ARROW '&' variable
			{ $$ = zend_ast_create_ex(ZEND_AST_ARRAY_ELEM, 1, $4, $1); }
	|	'&' variable
			{ $$ = zend_ast_create_ex(ZEND_AST_ARRAY_ELEM, 1, $2, NULL); }
	|	expr T_DOUBLE_ARROW T_LIST '(' array_pair_list ')'
			{ $5->attr = ZEND_ARRAY_SYNTAX_LIST;
			  $$ = zend_ast_create(ZEND_AST_ARRAY_ELEM, $5, $1); }
	|	T_LIST '(' array_pair_list ')'
			{ $3->attr = ZEND_ARRAY_SYNTAX_LIST;
			  $$ = zend_ast_create(ZEND_AST_ARRAY_ELEM, $3, NULL); }
;
encaps_list:
		encaps_list encaps_var
			{ $$ = zend_ast_list_add($1, $2); }
	|	encaps_list T_ENCAPSED_AND_WHITESPACE
			{ $$ = zend_ast_list_add($1, $2); }
	|	encaps_var
			{ $$ = zend_ast_create_list(1, ZEND_AST_ENCAPS_LIST, $1); }
	|	T_ENCAPSED_AND_WHITESPACE encaps_var
			{ $$ = zend_ast_create_list(2, ZEND_AST_ENCAPS_LIST, $1, $2); }
;
encaps_var:
		T_VARIABLE
			{ $$ = zend_ast_create(ZEND_AST_VAR, $1); }
	|	T_VARIABLE '[' encaps_var_offset ']'
			{ $$ = zend_ast_create(ZEND_AST_DIM,
			      zend_ast_create(ZEND_AST_VAR, $1), $3); }
	|	T_VARIABLE T_OBJECT_OPERATOR T_STRING
			{ $$ = zend_ast_create(ZEND_AST_PROP,
			      zend_ast_create(ZEND_AST_VAR, $1), $3); }
	|	T_DOLLAR_OPEN_CURLY_BRACES expr '}'
			{ $$ = zend_ast_create(ZEND_AST_VAR, $2); }
	|	T_DOLLAR_OPEN_CURLY_BRACES T_STRING_VARNAME '}'
			{ $$ = zend_ast_create(ZEND_AST_VAR, $2); }
	|	T_DOLLAR_OPEN_CURLY_BRACES T_STRING_VARNAME '[' expr ']' '}'
			{ $$ = zend_ast_create(ZEND_AST_DIM,
			      zend_ast_create(ZEND_AST_VAR, $2), $4); }
	|	T_CURLY_OPEN variable '}' { $$ = $2; }
;
encaps_var_offset:
		T_STRING			{ $$ = $1; }
	|	T_NUM_STRING		{ $$ = $1; }
	|	'-' T_NUM_STRING 	{ $$ = zend_negate_num_string($2); }
	|	T_VARIABLE			{ $$ = zend_ast_create(ZEND_AST_VAR, $1); }
;
internal_functions_in_yacc:
		T_ISSET '(' isset_variables possible_comma ')' { $$ = $3; }
	|	T_EMPTY '(' expr ')' { $$ = zend_ast_create(ZEND_AST_EMPTY, $3); }
	|	T_INCLUDE expr
			{ $$ = zend_ast_create_ex(ZEND_AST_INCLUDE_OR_EVAL, ZEND_INCLUDE, $2); }
	|	T_INCLUDE_ONCE expr
			{ $$ = zend_ast_create_ex(ZEND_AST_INCLUDE_OR_EVAL, ZEND_INCLUDE_ONCE, $2); }
	|	T_EVAL '(' expr ')'
			{ $$ = zend_ast_create_ex(ZEND_AST_INCLUDE_OR_EVAL, ZEND_EVAL, $3); }
	|	T_REQUIRE expr
			{ $$ = zend_ast_create_ex(ZEND_AST_INCLUDE_OR_EVAL, ZEND_REQUIRE, $2); }
	|	T_REQUIRE_ONCE expr
			{ $$ = zend_ast_create_ex(ZEND_AST_INCLUDE_OR_EVAL, ZEND_REQUIRE_ONCE, $2); }
;
isset_variables:
		isset_variable { $$ = $1; }
	|	isset_variables ',' isset_variable
			{ $$ = zend_ast_create(ZEND_AST_AND, $1, $3); }
;
isset_variable:
		expr { $$ = zend_ast_create(ZEND_AST_ISSET, $1); }
;
%%
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T zend_yytnamerr(char *yyres, const char *yystr)
{
	/* CG(parse_error) states:
	 * 0 => yyres = NULL, yystr is the unexpected token
	 * 1 => yyres = NULL, yystr is one of the expected tokens
	 * 2 => yyres != NULL, yystr is the unexpected token
	 * 3 => yyres != NULL, yystr is one of the expected tokens
	 */
	if (yyres && CG(parse_error) < 2) {
		CG(parse_error) = 2;
	}
	if (CG(parse_error) % 2 == 0) {
		/* The unexpected token */
		char buffer[120];
		const unsigned char *end, *str, *tok1 = NULL, *tok2 = NULL;
		unsigned int len = 0, toklen = 0, yystr_len;
		CG(parse_error)++;
		if (LANG_SCNG(yy_text)[0] == 0 &&
			LANG_SCNG(yy_leng) == 1 &&
			memcmp(yystr, "\"end of file\"", sizeof("\"end of file\"") - 1) == 0) {
			if (yyres) {
				yystpcpy(yyres, "end of file");
			}
			return sizeof("end of file")-1;
		}
		str = LANG_SCNG(yy_text);
		end = memchr(str, '\n', LANG_SCNG(yy_leng));
		yystr_len = (unsigned int)yystrlen(yystr);
		if ((tok1 = memchr(yystr, '(', yystr_len)) != NULL
			&& (tok2 = zend_memrchr(yystr, ')', yystr_len)) != NULL) {
			toklen = (tok2 - tok1) + 1;
		} else {
			tok1 = tok2 = NULL;
			toklen = 0;
		}
		if (end == NULL) {
			len = LANG_SCNG(yy_leng) > 30 ? 30 : LANG_SCNG(yy_leng);
		} else {
			len = (end - str) > 30 ? 30 : (end - str);
		}
		if (yyres) {
			if (toklen) {
				snprintf(buffer, sizeof(buffer), "'%.*s' %.*s", len, str, toklen, tok1);
			} else {
				snprintf(buffer, sizeof(buffer), "'%.*s'", len, str);
			}
			yystpcpy(yyres, buffer);
		}
		return len + (toklen ? toklen + 1 : 0) + 2;
	}
	/* One of the expected tokens */
	if (!yyres) {
		return yystrlen(yystr) - (*yystr == '"' ? 2 : 0);
	}
	if (*yystr == '"') {
		YYSIZE_T yyn = 0;
		const char *yyp = yystr;
		for (; *++yyp != '"'; ++yyn) {
			yyres[yyn] = *yyp;
		}
		yyres[yyn] = '\0';
		return yyn;
	}
	yystpcpy(yyres, yystr);
	return strlen(yystr);
}
/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * indent-tabs-mode: t
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
