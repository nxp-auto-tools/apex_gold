#ifndef ELFCPP_APEX_H
#define ELFCPP_APEX_H

#define R_APEX(I, N, S, D, PCR, E, M) N = I,

namespace elfcpp
{
  // sync with include/llvm/Support/ELFRelocs/APEX.def
  enum
  {
    R_APEX_NONE = -1,
    R_APEX(0, R_APEX_0, s15, 64, 0, (sym_add), 0x3fff8UL)
    R_APEX(1, R_APEX_1, u16, 64, 0, (sym_add), 0xffffUL)
    R_APEX(2, R_APEX_2, s16, 64, 0, (sym_add), 0xffffUL)
    R_APEX(3, R_APEX_3, u16, 64, 0, ((sym_add)&0xFFFF), 0xffffUL)
    R_APEX(4, R_APEX_4, s16, 64, 0, (((sym_add)>>16)&0xFFFF), 0xffffUL)
    R_APEX(5, R_APEX_5, s32, 32, 0, (sym_add), 0xffffffffUL)
    R_APEX(7, R_APEX_7, s16, 64, PC_REL, (((sym_add)-PC)-2), 0xffffUL)
    R_APEX(8, R_APEX_8, u16, 64, PC_REL, (((sym_add)-PC)-2), 0xffffUL)
    R_APEX(9, R_APEX_9, s16, 64, 0, ((sym_add)&0xFFFF), 0xffffUL)
    R_APEX(10, R_APEX_10, s6, 64, 0, ((sym_add)&0xFFFF), 0x3f000UL)
    R_APEX(11, R_APEX_11, s12, 64, 0, ((sym_add)&0xFFFF), 0x7ff8UL)
    R_APEX(12, R_APEX_12, s5, 64, 0, ((sym_add)&0xFFFF), 0x3e000UL)
    R_APEX(13, R_APEX_13, u5, 64, 0, ((sym_add)&0xFFFF), 0x7c0UL)
    R_APEX(14, R_APEX_14, u5, 64, 0, ((sym_add)&0xFFFF), 0xf800UL)
    R_APEX(15, R_APEX_15, s5, 64, 0, ((sym_add)&0xFFFF), 0xf800UL)
    R_APEX(16, R_APEX_16, u13, 64, 0, ((sym_add)&0xFFFF), 0x1fffUL)
    R_APEX(17, R_APEX_17, u13, 64, 0, ((sym_add)&0xFFFF), 0x3ffe000UL)
    R_APEX(18, R_APEX_18, u7, 64, 0, ((sym_add)&0xFFFF), 0x3f800UL)
    R_APEX(19, R_APEX_19, s16, 64, 0, ((sym_add)&0xFFFF), 0x7fff8UL)
    R_APEX(20, R_APEX_20, s10, 64, 0, ((sym_add)&0xFFFF), 0x3ffUL)
    R_APEX(21, R_APEX_21, u8, 64, 0, ((sym_add)&0xFFFF), 0x7f8000UL)
    R_APEX(22, R_APEX_22, u4, 64, 0, ((sym_add)&0xFFFF), 0x3cUL)
    R_APEX(23, R_APEX_23, u4, 64, 0, ((sym_add)&0xFFFF), 0xfUL)
    R_APEX(24, R_APEX_24, u4, 64, 0, ((sym_add)&0xFFFF), 0xf0000UL)
    R_APEX(25, R_APEX_25, u5, 64, 0, ((sym_add)&0xFFFF), 0xf8000UL)
    R_APEX(26, R_APEX_26, u4, 64, 0, ((sym_add)&0xFFFF), 0x3c000UL)
    R_APEX(27, R_APEX_27, u4, 64, 0, ((sym_add)&0xFFFF), 0x78UL)
    R_APEX(28, R_APEX_28, s5, 64, 0, ((sym_add)&0xFFFF), 0x1f000UL)
    R_APEX(29, R_APEX_29, s5, 64, 0, ((sym_add)&0xFFFF), 0x7cUL)
    R_APEX(30, R_APEX_30, s6, 64, 0, (((sym_add)>>16)&0xFFFF), 0x3f000UL)
    R_APEX(31, R_APEX_31, s12, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7ff8UL)
    R_APEX(32, R_APEX_32, u16, 64, 0, (((sym_add)>>16)&0xFFFF), 0xffffUL)
    R_APEX(33, R_APEX_33, s5, 64, 0, (((sym_add)>>16)&0xFFFF), 0x3e000UL)
    R_APEX(34, R_APEX_34, u5, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7c0UL)
    R_APEX(35, R_APEX_35, u5, 64, 0, (((sym_add)>>16)&0xFFFF), 0xf800UL)
    R_APEX(36, R_APEX_36, s5, 64, 0, (((sym_add)>>16)&0xFFFF), 0xf800UL)
    R_APEX(37, R_APEX_37, u13, 64, 0, (((sym_add)>>16)&0xFFFF), 0x3ffe000UL)
    R_APEX(38, R_APEX_38, u7, 64, 0, (((sym_add)>>16)&0xFFFF), 0x3f800UL)
    R_APEX(39, R_APEX_39, s16, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7fff8UL)
    R_APEX(40, R_APEX_40, s10, 64, 0, (((sym_add)>>16)&0xFFFF), 0x3ffUL)
    R_APEX(41, R_APEX_41, u8, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7f8000UL)
    R_APEX(42, R_APEX_42, u4, 64, 0, (((sym_add)>>16)&0xFFFF), 0x3cUL)
    R_APEX(43, R_APEX_43, u4, 64, 0, (((sym_add)>>16)&0xFFFF), 0xfUL)
    R_APEX(44, R_APEX_44, u4, 64, 0, (((sym_add)>>16)&0xFFFF), 0xf0000UL)
    R_APEX(45, R_APEX_45, u5, 64, 0, (((sym_add)>>16)&0xFFFF), 0xf8000UL)
    R_APEX(46, R_APEX_46, u4, 64, 0, (((sym_add)>>16)&0xFFFF), 0x3c000UL)
    R_APEX(47, R_APEX_47, u4, 64, 0, (((sym_add)>>16)&0xFFFF), 0x78UL)
    R_APEX(48, R_APEX_48, s5, 64, 0, (((sym_add)>>16)&0xFFFF), 0x1f000UL)
    R_APEX(49, R_APEX_49, s5, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7cUL)
    R_APEX(50, R_APEX_50, s6, 64, 0, (sym_add), 0x3f000UL)
    R_APEX(51, R_APEX_51, s12, 64, 0, (sym_add), 0x7ff8UL)
    R_APEX(52, R_APEX_52, s5, 64, 0, (sym_add), 0x3e000UL)
    R_APEX(53, R_APEX_53, u5, 64, 0, (sym_add), 0x7c0UL)
    R_APEX(54, R_APEX_54, u5, 64, 0, (sym_add), 0xf800UL)
    R_APEX(55, R_APEX_55, s5, 64, 0, (sym_add), 0xf800UL)
    R_APEX(56, R_APEX_56, u13, 64, 0, (sym_add), 0x3ffe000UL)
    R_APEX(57, R_APEX_57, u7, 64, 0, (sym_add), 0x3f800UL)
    R_APEX(58, R_APEX_58, s16, 64, 0, (sym_add), 0x7fff8UL)
    R_APEX(59, R_APEX_59, s10, 64, 0, (sym_add), 0x3ffUL)
    R_APEX(60, R_APEX_60, u8, 64, 0, (sym_add), 0x7f8000UL)
    R_APEX(61, R_APEX_61, u4, 64, 0, (sym_add), 0x3cUL)
    R_APEX(62, R_APEX_62, u4, 64, 0, (sym_add), 0xfUL)
    R_APEX(63, R_APEX_63, u4, 64, 0, (sym_add), 0xf0000UL)
    R_APEX(64, R_APEX_64, u5, 64, 0, (sym_add), 0xf8000UL)
    R_APEX(65, R_APEX_65, u4, 64, 0, (sym_add), 0x3c000UL)
    R_APEX(66, R_APEX_66, u4, 64, 0, (sym_add), 0x78UL)
    R_APEX(67, R_APEX_67, s5, 64, 0, (sym_add), 0x1f000UL)
    R_APEX(68, R_APEX_68, s5, 64, 0, (sym_add), 0x7cUL)
    R_APEX(69, R_APEX_69, s16, 32, PC_REL, (((sym_add)-PC)-2), 0xffffUL)
    R_APEX(70, R_APEX_70, s16, 64, PC_REL, (((sym_add)-PC)-2), 0xffff00000000UL)
    R_APEX(71, R_APEX_71, s16, 32, PC_REL, (((sym_add)-PC)-3), 0xffffUL)
    R_APEX(72, R_APEX_72, s16, 64, PC_REL, (((sym_add)-PC)-3), 0xffff00000000UL)
    R_APEX(73, R_APEX_73, s16, 32, PC_REL, (((sym_add)-PC)-4), 0xffffUL)
    R_APEX(74, R_APEX_74, s16, 64, PC_REL, (((sym_add)-PC)-4), 0xffff00000000UL)
    R_APEX(75, R_APEX_75, s25, 32, PC_REL, (((sym_add)-PC)-1), 0x1ffffffUL)
    R_APEX(76, R_APEX_76, s25, 64, PC_REL, (((sym_add)-PC)-1), 0x1ffffff00000000UL)
    R_APEX(77, R_APEX_77, s25, 32, PC_REL, (((sym_add)-PC)-2), 0x1ffffffUL)
    R_APEX(78, R_APEX_78, s25, 64, PC_REL, (((sym_add)-PC)-2), 0x1ffffff00000000UL)
    R_APEX(79, R_APEX_79, u16, 32, PC_REL, (((sym_add)-PC)-2), 0xffffUL)
    R_APEX(80, R_APEX_80, u16, 64, PC_REL, (((sym_add)-PC)-2), 0xffff00000000UL)
    R_APEX(81, R_APEX_81, u16, 32, PC_REL, (((sym_add)-PC)-3), 0xffffUL)
    R_APEX(82, R_APEX_82, u16, 64, PC_REL, (((sym_add)-PC)-3), 0xffff00000000UL)
    R_APEX(83, R_APEX_83, u16, 32, PC_REL, (((sym_add)-PC)-4), 0xffffUL)
    R_APEX(84, R_APEX_84, u16, 64, PC_REL, (((sym_add)-PC)-4), 0xffff00000000UL)
    R_APEX(85, R_APEX_85, u13, 32, PC_REL, (((sym_add)-PC)-2), 0x1fffUL)
    R_APEX(86, R_APEX_86, u13, 64, PC_REL, (((sym_add)-PC)-2), 0x1fff00000000UL)
    R_APEX(87, R_APEX_87, u13, 32, PC_REL, (((sym_add)-PC)-3), 0x1fffUL)
    R_APEX(88, R_APEX_88, u13, 64, PC_REL, (((sym_add)-PC)-3), 0x1fff00000000UL)
    R_APEX(89, R_APEX_89, u13, 32, PC_REL, (((sym_add)-PC)-4), 0x1fffUL)
    R_APEX(90, R_APEX_90, u13, 64, PC_REL, (((sym_add)-PC)-4), 0x1fff00000000UL)
    R_APEX(91, R_APEX_91, s15, 32, 0, ((sym_add)&0xFFFF), 0x7fffUL)
    R_APEX(92, R_APEX_92, s15, 64, 0, ((sym_add)&0xFFFF), 0x7fff00000000UL)
    R_APEX(93, R_APEX_93, s15, 64, 0, ((sym_add)&0xFFFF), 0x1fffc000UL)
    R_APEX(94, R_APEX_94, s12, 32, 0, ((sym_add)&0xFFFF), 0x7ff8UL)
    R_APEX(95, R_APEX_95, s12, 64, 0, ((sym_add)&0xFFFF), 0x7ff8UL)
    R_APEX(96, R_APEX_96, s12, 64, 0, ((sym_add)&0xFFFF), 0xfff0000UL)
    R_APEX(97, R_APEX_97, s16, 32, 0, ((sym_add)&0xFFFF), 0x7fff8UL)
    R_APEX(98, R_APEX_98, s16, 64, 0, ((sym_add)&0xFFFF), 0x7fff8UL)
    R_APEX(99, R_APEX_99, s16, 64, 0, ((sym_add)&0xFFFF), 0x180003fffUL)
    R_APEX(100, R_APEX_100, s32, 64, 0, ((sym_add)&0xFFFF), 0xffffffffUL)
    R_APEX(101, R_APEX_101, u16, 32, 0, ((sym_add)&0xFFFF), 0xffffUL)
    R_APEX(102, R_APEX_102, u16, 64, 0, ((sym_add)&0xFFFF), 0xffff00000000UL)
    R_APEX(103, R_APEX_103, u15, 32, 0, ((sym_add)&0xFFFF), 0x7fffUL)
    R_APEX(104, R_APEX_104, u15, 64, 0, ((sym_add)&0xFFFF), 0x7fff00000000UL)
    R_APEX(105, R_APEX_105, s16, 32, 0, ((sym_add)&0xFFFF), 0xffffUL)
    R_APEX(106, R_APEX_106, s16, 64, 0, ((sym_add)&0xFFFF), 0xffff00000000UL)
    R_APEX(107, R_APEX_107, u5, 32, 0, ((sym_add)&0xFFFF), 0x3e0UL)
    R_APEX(108, R_APEX_108, u5, 64, 0, ((sym_add)&0xFFFF), 0x3e000000000UL)
    R_APEX(109, R_APEX_109, u5, 32, 0, ((sym_add)&0xFFFF), 0x7c00UL)
    R_APEX(110, R_APEX_110, u5, 64, 0, ((sym_add)&0xFFFF), 0x7c0000000000UL)
    R_APEX(111, R_APEX_111, s6, 32, 0, ((sym_add)&0xFFFF), 0x7e00UL)
    R_APEX(112, R_APEX_112, s6, 64, 0, ((sym_add)&0xFFFF), 0x7e0000000000UL)
    R_APEX(113, R_APEX_113, s5, 32, 0, ((sym_add)&0xFFFF), 0x7c00UL)
    R_APEX(114, R_APEX_114, s5, 64, 0, ((sym_add)&0xFFFF), 0x7c0000000000UL)
    R_APEX(115, R_APEX_115, s5, 64, 0, ((sym_add)&0xFFFF), 0x7c000UL)
    R_APEX(116, R_APEX_116, u13, 32, 0, ((sym_add)&0xFFFF), 0x1fffUL)
    R_APEX(117, R_APEX_117, u13, 64, 0, ((sym_add)&0xFFFF), 0x1fff00000000UL)
    R_APEX(118, R_APEX_118, u12, 32, 0, ((sym_add)&0xFFFF), 0x1ffe000UL)
    R_APEX(119, R_APEX_119, u12, 64, 0, ((sym_add)&0xFFFF), 0x1ffe00000000000UL)
    R_APEX(120, R_APEX_120, u7, 32, 0, ((sym_add)&0xFFFF), 0x1fc00UL)
    R_APEX(121, R_APEX_121, u7, 64, 0, ((sym_add)&0xFFFF), 0x1fc00UL)
    R_APEX(122, R_APEX_122, u8, 32, 0, ((sym_add)&0xFFFF), 0x3fc000UL)
    R_APEX(123, R_APEX_123, u8, 64, 0, ((sym_add)&0xFFFF), 0x3fc000UL)
    R_APEX(124, R_APEX_124, s16, 64, 0, ((sym_add)&0xFFFF), 0xf80001ffc000UL)
    R_APEX(125, R_APEX_125, u5, 32, 0, ((sym_add)&0xFFFF), 0x7c000UL)
    R_APEX(126, R_APEX_126, u5, 64, 0, ((sym_add)&0xFFFF), 0x7c000UL)
    R_APEX(127, R_APEX_127, u4, 32, 0, ((sym_add)&0xFFFF), 0xfUL)
    R_APEX(128, R_APEX_128, u4, 64, 0, ((sym_add)&0xFFFF), 0xfUL)
    R_APEX(129, R_APEX_129, u4, 32, 0, ((sym_add)&0xFFFF), 0x78000UL)
    R_APEX(130, R_APEX_130, u4, 64, 0, ((sym_add)&0xFFFF), 0x78000UL)
    R_APEX(131, R_APEX_131, s5, 32, 0, ((sym_add)&0xFFFF), 0x7c000UL)
    R_APEX(132, R_APEX_132, u8, 32, 0, ((sym_add)&0xFFFF), 0x7f8UL)
    R_APEX(133, R_APEX_133, u8, 64, 0, ((sym_add)&0xFFFF), 0x7f8UL)
    R_APEX(134, R_APEX_134, u4, 64, 0, ((sym_add)&0xFFFF), 0x3c000UL)
    R_APEX(135, R_APEX_135, s5, 32, 0, ((sym_add)&0xFFFF), 0xf800UL)
    R_APEX(136, R_APEX_136, s5, 64, 0, ((sym_add)&0xFFFF), 0xf800UL)
    R_APEX(137, R_APEX_137, s13, 32, 0, ((sym_add)&0xFFFF), 0xffc07UL)
    R_APEX(138, R_APEX_138, s13, 64, 0, ((sym_add)&0xFFFF), 0xffc07UL)
    R_APEX(139, R_APEX_139, s5, 32, 0, ((sym_add)&0xFFFF), 0x1fUL)
    R_APEX(140, R_APEX_140, s5, 64, 0, ((sym_add)&0xFFFF), 0x1fUL)
    R_APEX(141, R_APEX_141, s15, 32, 0, (((sym_add)>>16)&0xFFFF), 0x7fffUL)
    R_APEX(142, R_APEX_142, s15, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7fff00000000UL)
    R_APEX(143, R_APEX_143, s15, 64, 0, (((sym_add)>>16)&0xFFFF), 0x1fffc000UL)
    R_APEX(144, R_APEX_144, s12, 32, 0, (((sym_add)>>16)&0xFFFF), 0x7ff8UL)
    R_APEX(145, R_APEX_145, s12, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7ff8UL)
    R_APEX(146, R_APEX_146, s12, 64, 0, (((sym_add)>>16)&0xFFFF), 0xfff0000UL)
    R_APEX(147, R_APEX_147, s16, 32, 0, (((sym_add)>>16)&0xFFFF), 0x7fff8UL)
    R_APEX(148, R_APEX_148, s16, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7fff8UL)
    R_APEX(149, R_APEX_149, s16, 64, 0, (((sym_add)>>16)&0xFFFF), 0x180003fffUL)
    R_APEX(150, R_APEX_150, s32, 64, 0, (((sym_add)>>16)&0xFFFF), 0xffffffffUL)
    R_APEX(151, R_APEX_151, u16, 32, 0, (((sym_add)>>16)&0xFFFF), 0xffffUL)
    R_APEX(152, R_APEX_152, u16, 64, 0, (((sym_add)>>16)&0xFFFF), 0xffff00000000UL)
    R_APEX(153, R_APEX_153, u15, 32, 0, (((sym_add)>>16)&0xFFFF), 0x7fffUL)
    R_APEX(154, R_APEX_154, u15, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7fff00000000UL)
    R_APEX(155, R_APEX_155, s16, 32, 0, (((sym_add)>>16)&0xFFFF), 0xffffUL)
    R_APEX(156, R_APEX_156, s16, 64, 0, (((sym_add)>>16)&0xFFFF), 0xffff00000000UL)
    R_APEX(157, R_APEX_157, u5, 32, 0, (((sym_add)>>16)&0xFFFF), 0x3e0UL)
    R_APEX(158, R_APEX_158, u5, 64, 0, (((sym_add)>>16)&0xFFFF), 0x3e000000000UL)
    R_APEX(159, R_APEX_159, u5, 32, 0, (((sym_add)>>16)&0xFFFF), 0x7c00UL)
    R_APEX(160, R_APEX_160, u5, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7c0000000000UL)
    R_APEX(161, R_APEX_161, s6, 32, 0, (((sym_add)>>16)&0xFFFF), 0x7e00UL)
    R_APEX(162, R_APEX_162, s6, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7e0000000000UL)
    R_APEX(163, R_APEX_163, s5, 32, 0, (((sym_add)>>16)&0xFFFF), 0x7c00UL)
    R_APEX(164, R_APEX_164, s5, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7c0000000000UL)
    R_APEX(165, R_APEX_165, s5, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7c000UL)
    R_APEX(166, R_APEX_166, u12, 32, 0, (((sym_add)>>16)&0xFFFF), 0x1ffe000UL)
    R_APEX(167, R_APEX_167, u12, 64, 0, (((sym_add)>>16)&0xFFFF), 0x1ffe00000000000UL)
    R_APEX(168, R_APEX_168, u7, 32, 0, (((sym_add)>>16)&0xFFFF), 0x1fc00UL)
    R_APEX(169, R_APEX_169, u7, 64, 0, (((sym_add)>>16)&0xFFFF), 0x1fc00UL)
    R_APEX(170, R_APEX_170, u8, 32, 0, (((sym_add)>>16)&0xFFFF), 0x3fc000UL)
    R_APEX(171, R_APEX_171, u8, 64, 0, (((sym_add)>>16)&0xFFFF), 0x3fc000UL)
    R_APEX(172, R_APEX_172, s16, 64, 0, (((sym_add)>>16)&0xFFFF), 0xf80001ffc000UL)
    R_APEX(173, R_APEX_173, u5, 32, 0, (((sym_add)>>16)&0xFFFF), 0x7c000UL)
    R_APEX(174, R_APEX_174, u5, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7c000UL)
    R_APEX(175, R_APEX_175, u4, 32, 0, (((sym_add)>>16)&0xFFFF), 0xfUL)
    R_APEX(176, R_APEX_176, u4, 64, 0, (((sym_add)>>16)&0xFFFF), 0xfUL)
    R_APEX(177, R_APEX_177, u4, 32, 0, (((sym_add)>>16)&0xFFFF), 0x78000UL)
    R_APEX(178, R_APEX_178, u4, 64, 0, (((sym_add)>>16)&0xFFFF), 0x78000UL)
    R_APEX(179, R_APEX_179, s5, 32, 0, (((sym_add)>>16)&0xFFFF), 0x7c000UL)
    R_APEX(180, R_APEX_180, u8, 32, 0, (((sym_add)>>16)&0xFFFF), 0x7f8UL)
    R_APEX(181, R_APEX_181, u8, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7f8UL)
    R_APEX(182, R_APEX_182, u4, 64, 0, (((sym_add)>>16)&0xFFFF), 0x3c000UL)
    R_APEX(183, R_APEX_183, s5, 32, 0, (((sym_add)>>16)&0xFFFF), 0xf800UL)
    R_APEX(184, R_APEX_184, s5, 64, 0, (((sym_add)>>16)&0xFFFF), 0xf800UL)
    R_APEX(185, R_APEX_185, s13, 32, 0, (((sym_add)>>16)&0xFFFF), 0xffc07UL)
    R_APEX(186, R_APEX_186, s13, 64, 0, (((sym_add)>>16)&0xFFFF), 0xffc07UL)
    R_APEX(187, R_APEX_187, s5, 32, 0, (((sym_add)>>16)&0xFFFF), 0x1fUL)
    R_APEX(188, R_APEX_188, s5, 64, 0, (((sym_add)>>16)&0xFFFF), 0x1fUL)
    R_APEX(189, R_APEX_189, s15, 32, 0, (sym_add), 0x7fffUL)
    R_APEX(190, R_APEX_190, s15, 64, 0, (sym_add), 0x7fff00000000UL)
    R_APEX(191, R_APEX_191, s15, 64, 0, (sym_add), 0x1fffc000UL)
    R_APEX(192, R_APEX_192, s12, 32, 0, (sym_add), 0x7ff8UL)
    R_APEX(193, R_APEX_193, s12, 64, 0, (sym_add), 0x7ff8UL)
    R_APEX(194, R_APEX_194, s12, 64, 0, (sym_add), 0xfff0000UL)
    R_APEX(195, R_APEX_195, s16, 32, 0, (sym_add), 0x7fff8UL)
    R_APEX(196, R_APEX_196, s16, 64, 0, (sym_add), 0x7fff8UL)
    R_APEX(197, R_APEX_197, s16, 64, 0, (sym_add), 0x180003fffUL)
    R_APEX(198, R_APEX_198, s32, 64, 0, (sym_add), 0xffffffffUL)
    R_APEX(199, R_APEX_199, u16, 32, 0, (sym_add), 0xffffUL)
    R_APEX(200, R_APEX_200, u16, 64, 0, (sym_add), 0xffff00000000UL)
    R_APEX(201, R_APEX_201, u15, 32, 0, (sym_add), 0x7fffUL)
    R_APEX(202, R_APEX_202, u15, 64, 0, (sym_add), 0x7fff00000000UL)
    R_APEX(203, R_APEX_203, s16, 32, 0, (sym_add), 0xffffUL)
    R_APEX(204, R_APEX_204, s16, 64, 0, (sym_add), 0xffff00000000UL)
    R_APEX(205, R_APEX_205, u5, 32, 0, (sym_add), 0x3e0UL)
    R_APEX(206, R_APEX_206, u5, 64, 0, (sym_add), 0x3e000000000UL)
    R_APEX(207, R_APEX_207, u5, 32, 0, (sym_add), 0x7c00UL)
    R_APEX(208, R_APEX_208, u5, 64, 0, (sym_add), 0x7c0000000000UL)
    R_APEX(209, R_APEX_209, s6, 32, 0, (sym_add), 0x7e00UL)
    R_APEX(210, R_APEX_210, s6, 64, 0, (sym_add), 0x7e0000000000UL)
    R_APEX(211, R_APEX_211, s5, 32, 0, (sym_add), 0x7c00UL)
    R_APEX(212, R_APEX_212, s5, 64, 0, (sym_add), 0x7c0000000000UL)
    R_APEX(213, R_APEX_213, s5, 64, 0, (sym_add), 0x7c000UL)
    R_APEX(214, R_APEX_214, u12, 32, 0, (sym_add), 0x1ffe000UL)
    R_APEX(215, R_APEX_215, u12, 64, 0, (sym_add), 0x1ffe00000000000UL)
    R_APEX(216, R_APEX_216, u7, 32, 0, (sym_add), 0x1fc00UL)
    R_APEX(217, R_APEX_217, u7, 64, 0, (sym_add), 0x1fc00UL)
    R_APEX(218, R_APEX_218, u8, 32, 0, (sym_add), 0x3fc000UL)
    R_APEX(219, R_APEX_219, u8, 64, 0, (sym_add), 0x3fc000UL)
    R_APEX(220, R_APEX_220, s16, 64, 0, (sym_add), 0xf80001ffc000UL)
    R_APEX(221, R_APEX_221, u5, 32, 0, (sym_add), 0x7c000UL)
    R_APEX(222, R_APEX_222, u5, 64, 0, (sym_add), 0x7c000UL)
    R_APEX(223, R_APEX_223, u4, 32, 0, (sym_add), 0xfUL)
    R_APEX(224, R_APEX_224, u4, 64, 0, (sym_add), 0xfUL)
    R_APEX(225, R_APEX_225, u4, 32, 0, (sym_add), 0x78000UL)
    R_APEX(226, R_APEX_226, u4, 64, 0, (sym_add), 0x78000UL)
    R_APEX(227, R_APEX_227, s5, 32, 0, (sym_add), 0x7c000UL)
    R_APEX(228, R_APEX_228, u8, 32, 0, (sym_add), 0x7f8UL)
    R_APEX(229, R_APEX_229, u8, 64, 0, (sym_add), 0x7f8UL)
    R_APEX(230, R_APEX_230, u4, 64, 0, (sym_add), 0x3c000UL)
    R_APEX(231, R_APEX_231, s5, 32, 0, (sym_add), 0xf800UL)
    R_APEX(232, R_APEX_232, s5, 64, 0, (sym_add), 0xf800UL)
    R_APEX(233, R_APEX_233, s13, 32, 0, (sym_add), 0xffc07UL)
    R_APEX(234, R_APEX_234, s13, 64, 0, (sym_add), 0xffc07UL)
    R_APEX(235, R_APEX_235, s5, 32, 0, (sym_add), 0x1fUL)
    R_APEX(236, R_APEX_236, s5, 64, 0, (sym_add), 0x1fUL)
    R_APEX(237, R_APEX_237, s32, 32, 0, (sym_add), 0xffffffffUL)
    R_APEX(238, R_APEX_238, s8, 32, 0, ((sym_add)&0xFFFF), 0x7c07UL)
    R_APEX(239, R_APEX_239, s8, 64, 0, ((sym_add)&0xFFFF), 0x7c07UL)
    R_APEX(240, R_APEX_240, u6, 64, 0, ((sym_add)&0xFFFF), 0xfc000000UL)
    R_APEX(241, R_APEX_241, s8, 32, 0, (((sym_add)>>16)&0xFFFF), 0x7c07UL)
    R_APEX(242, R_APEX_242, s8, 64, 0, (((sym_add)>>16)&0xFFFF), 0x7c07UL)
    R_APEX(243, R_APEX_243, u6, 64, 0, (((sym_add)>>16)&0xFFFF), 0xfc000000UL)
    R_APEX(244, R_APEX_244, s8, 32, 0, (sym_add), 0x7c07UL)
    R_APEX(245, R_APEX_245, s8, 64, 0, (sym_add), 0x7c07UL)
    R_APEX(246, R_APEX_246, u6, 64, 0, (sym_add), 0xfc000000UL)
    R_APEX_COPY = 999
  };
} // End namespace elfcpp

#endif // !defined(ELFCPP_APEX_H)
