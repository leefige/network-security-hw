
vul32:     file format elf32-i386


Disassembly of section .init:

08048408 <_init>:
 8048408:	53                   	push   %ebx
 8048409:	83 ec 08             	sub    $0x8,%esp
 804840c:	e8 ef 00 00 00       	call   8048500 <__x86.get_pc_thunk.bx>
 8048411:	81 c3 ef 1b 00 00    	add    $0x1bef,%ebx
 8048417:	8b 83 fc ff ff ff    	mov    -0x4(%ebx),%eax
 804841d:	85 c0                	test   %eax,%eax
 804841f:	74 05                	je     8048426 <_init+0x1e>
 8048421:	e8 5a 00 00 00       	call   8048480 <__gmon_start__@plt>
 8048426:	83 c4 08             	add    $0x8,%esp
 8048429:	5b                   	pop    %ebx
 804842a:	c3                   	ret    

Disassembly of section .plt:

08048430 <setbuf@plt-0x10>:
 8048430:	ff 35 04 a0 04 08    	pushl  0x804a004
 8048436:	ff 25 08 a0 04 08    	jmp    *0x804a008
 804843c:	00 00                	add    %al,(%eax)
	...

08048440 <setbuf@plt>:
 8048440:	ff 25 0c a0 04 08    	jmp    *0x804a00c
 8048446:	68 00 00 00 00       	push   $0x0
 804844b:	e9 e0 ff ff ff       	jmp    8048430 <_init+0x28>

08048450 <read@plt>:
 8048450:	ff 25 10 a0 04 08    	jmp    *0x804a010
 8048456:	68 08 00 00 00       	push   $0x8
 804845b:	e9 d0 ff ff ff       	jmp    8048430 <_init+0x28>

08048460 <__stack_chk_fail@plt>:
 8048460:	ff 25 14 a0 04 08    	jmp    *0x804a014
 8048466:	68 10 00 00 00       	push   $0x10
 804846b:	e9 c0 ff ff ff       	jmp    8048430 <_init+0x28>

08048470 <puts@plt>:
 8048470:	ff 25 18 a0 04 08    	jmp    *0x804a018
 8048476:	68 18 00 00 00       	push   $0x18
 804847b:	e9 b0 ff ff ff       	jmp    8048430 <_init+0x28>

08048480 <__gmon_start__@plt>:
 8048480:	ff 25 1c a0 04 08    	jmp    *0x804a01c
 8048486:	68 20 00 00 00       	push   $0x20
 804848b:	e9 a0 ff ff ff       	jmp    8048430 <_init+0x28>

08048490 <exit@plt>:
 8048490:	ff 25 20 a0 04 08    	jmp    *0x804a020
 8048496:	68 28 00 00 00       	push   $0x28
 804849b:	e9 90 ff ff ff       	jmp    8048430 <_init+0x28>

080484a0 <__libc_start_main@plt>:
 80484a0:	ff 25 24 a0 04 08    	jmp    *0x804a024
 80484a6:	68 30 00 00 00       	push   $0x30
 80484ab:	e9 80 ff ff ff       	jmp    8048430 <_init+0x28>

080484b0 <write@plt>:
 80484b0:	ff 25 28 a0 04 08    	jmp    *0x804a028
 80484b6:	68 38 00 00 00       	push   $0x38
 80484bb:	e9 70 ff ff ff       	jmp    8048430 <_init+0x28>

080484c0 <memset@plt>:
 80484c0:	ff 25 2c a0 04 08    	jmp    *0x804a02c
 80484c6:	68 40 00 00 00       	push   $0x40
 80484cb:	e9 60 ff ff ff       	jmp    8048430 <_init+0x28>

Disassembly of section .text:

080484d0 <_start>:
 80484d0:	31 ed                	xor    %ebp,%ebp
 80484d2:	5e                   	pop    %esi
 80484d3:	89 e1                	mov    %esp,%ecx
 80484d5:	83 e4 f0             	and    $0xfffffff0,%esp
 80484d8:	50                   	push   %eax
 80484d9:	54                   	push   %esp
 80484da:	52                   	push   %edx
 80484db:	68 30 87 04 08       	push   $0x8048730
 80484e0:	68 d0 86 04 08       	push   $0x80486d0
 80484e5:	51                   	push   %ecx
 80484e6:	56                   	push   %esi
 80484e7:	68 5c 86 04 08       	push   $0x804865c
 80484ec:	e8 af ff ff ff       	call   80484a0 <__libc_start_main@plt>
 80484f1:	f4                   	hlt    
 80484f2:	66 90                	xchg   %ax,%ax
 80484f4:	66 90                	xchg   %ax,%ax
 80484f6:	66 90                	xchg   %ax,%ax
 80484f8:	66 90                	xchg   %ax,%ax
 80484fa:	66 90                	xchg   %ax,%ax
 80484fc:	66 90                	xchg   %ax,%ax
 80484fe:	66 90                	xchg   %ax,%ax

08048500 <__x86.get_pc_thunk.bx>:
 8048500:	8b 1c 24             	mov    (%esp),%ebx
 8048503:	c3                   	ret    
 8048504:	66 90                	xchg   %ax,%ax
 8048506:	66 90                	xchg   %ax,%ax
 8048508:	66 90                	xchg   %ax,%ax
 804850a:	66 90                	xchg   %ax,%ax
 804850c:	66 90                	xchg   %ax,%ax
 804850e:	66 90                	xchg   %ax,%ax

08048510 <deregister_tm_clones>:
 8048510:	b8 5b a0 04 08       	mov    $0x804a05b,%eax
 8048515:	2d 58 a0 04 08       	sub    $0x804a058,%eax
 804851a:	83 f8 06             	cmp    $0x6,%eax
 804851d:	76 1a                	jbe    8048539 <deregister_tm_clones+0x29>
 804851f:	b8 00 00 00 00       	mov    $0x0,%eax
 8048524:	85 c0                	test   %eax,%eax
 8048526:	74 11                	je     8048539 <deregister_tm_clones+0x29>
 8048528:	55                   	push   %ebp
 8048529:	89 e5                	mov    %esp,%ebp
 804852b:	83 ec 14             	sub    $0x14,%esp
 804852e:	68 58 a0 04 08       	push   $0x804a058
 8048533:	ff d0                	call   *%eax
 8048535:	83 c4 10             	add    $0x10,%esp
 8048538:	c9                   	leave  
 8048539:	f3 c3                	repz ret 
 804853b:	90                   	nop
 804853c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi

08048540 <register_tm_clones>:
 8048540:	b8 58 a0 04 08       	mov    $0x804a058,%eax
 8048545:	2d 58 a0 04 08       	sub    $0x804a058,%eax
 804854a:	c1 f8 02             	sar    $0x2,%eax
 804854d:	89 c2                	mov    %eax,%edx
 804854f:	c1 ea 1f             	shr    $0x1f,%edx
 8048552:	01 d0                	add    %edx,%eax
 8048554:	d1 f8                	sar    %eax
 8048556:	74 1b                	je     8048573 <register_tm_clones+0x33>
 8048558:	ba 00 00 00 00       	mov    $0x0,%edx
 804855d:	85 d2                	test   %edx,%edx
 804855f:	74 12                	je     8048573 <register_tm_clones+0x33>
 8048561:	55                   	push   %ebp
 8048562:	89 e5                	mov    %esp,%ebp
 8048564:	83 ec 10             	sub    $0x10,%esp
 8048567:	50                   	push   %eax
 8048568:	68 58 a0 04 08       	push   $0x804a058
 804856d:	ff d2                	call   *%edx
 804856f:	83 c4 10             	add    $0x10,%esp
 8048572:	c9                   	leave  
 8048573:	f3 c3                	repz ret 
 8048575:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
 8048579:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi

08048580 <__do_global_dtors_aux>:
 8048580:	80 3d 88 a0 04 08 00 	cmpb   $0x0,0x804a088
 8048587:	75 13                	jne    804859c <__do_global_dtors_aux+0x1c>
 8048589:	55                   	push   %ebp
 804858a:	89 e5                	mov    %esp,%ebp
 804858c:	83 ec 08             	sub    $0x8,%esp
 804858f:	e8 7c ff ff ff       	call   8048510 <deregister_tm_clones>
 8048594:	c6 05 88 a0 04 08 01 	movb   $0x1,0x804a088
 804859b:	c9                   	leave  
 804859c:	f3 c3                	repz ret 
 804859e:	66 90                	xchg   %ax,%ax

080485a0 <frame_dummy>:
 80485a0:	b8 10 9f 04 08       	mov    $0x8049f10,%eax
 80485a5:	8b 10                	mov    (%eax),%edx
 80485a7:	85 d2                	test   %edx,%edx
 80485a9:	75 05                	jne    80485b0 <frame_dummy+0x10>
 80485ab:	eb 93                	jmp    8048540 <register_tm_clones>
 80485ad:	8d 76 00             	lea    0x0(%esi),%esi
 80485b0:	ba 00 00 00 00       	mov    $0x0,%edx
 80485b5:	85 d2                	test   %edx,%edx
 80485b7:	74 f2                	je     80485ab <frame_dummy+0xb>
 80485b9:	55                   	push   %ebp
 80485ba:	89 e5                	mov    %esp,%ebp
 80485bc:	83 ec 14             	sub    $0x14,%esp
 80485bf:	50                   	push   %eax
 80485c0:	ff d2                	call   *%edx
 80485c2:	83 c4 10             	add    $0x10,%esp
 80485c5:	c9                   	leave  
 80485c6:	e9 75 ff ff ff       	jmp    8048540 <register_tm_clones>

080485cb <dovuln>:
 80485cb:	55                   	push   %ebp
 80485cc:	89 e5                	mov    %esp,%ebp
 80485ce:	83 ec 48             	sub    $0x48,%esp
 80485d1:	65 a1 14 00 00 00    	mov    %gs:0x14,%eax
 80485d7:	89 45 f4             	mov    %eax,-0xc(%ebp)
 80485da:	31 c0                	xor    %eax,%eax
 80485dc:	83 ec 04             	sub    $0x4,%esp
 80485df:	6a 30                	push   $0x30
 80485e1:	6a 00                	push   $0x0
 80485e3:	8d 45 bc             	lea    -0x44(%ebp),%eax
 80485e6:	83 c0 01             	add    $0x1,%eax
 80485e9:	50                   	push   %eax
 80485ea:	e8 d1 fe ff ff       	call   80484c0 <memset@plt>
 80485ef:	83 c4 10             	add    $0x10,%esp
 80485f2:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%ebp)
 80485f9:	83 ec 04             	sub    $0x4,%esp
 80485fc:	6a 01                	push   $0x1
 80485fe:	8d 45 bc             	lea    -0x44(%ebp),%eax
 8048601:	50                   	push   %eax
 8048602:	6a 00                	push   $0x0
 8048604:	e8 47 fe ff ff       	call   8048450 <read@plt>
 8048609:	83 c4 10             	add    $0x10,%esp
 804860c:	83 f8 01             	cmp    $0x1,%eax
 804860f:	74 0a                	je     804861b <dovuln+0x50>
 8048611:	83 ec 0c             	sub    $0xc,%esp
 8048614:	6a 00                	push   $0x0
 8048616:	e8 75 fe ff ff       	call   8048490 <exit@plt>
 804861b:	0f b6 45 bc          	movzbl -0x44(%ebp),%eax
 804861f:	3c 0a                	cmp    $0xa,%al
 8048621:	74 13                	je     8048636 <dovuln+0x6b>
 8048623:	8b 45 f0             	mov    -0x10(%ebp),%eax
 8048626:	8d 50 01             	lea    0x1(%eax),%edx
 8048629:	89 55 f0             	mov    %edx,-0x10(%ebp)
 804862c:	0f b6 55 bc          	movzbl -0x44(%ebp),%edx
 8048630:	88 54 05 bd          	mov    %dl,-0x43(%ebp,%eax,1)
 8048634:	eb c3                	jmp    80485f9 <dovuln+0x2e>
 8048636:	90                   	nop
 8048637:	83 ec 0c             	sub    $0xc,%esp
 804863a:	8d 45 bc             	lea    -0x44(%ebp),%eax
 804863d:	83 c0 01             	add    $0x1,%eax
 8048640:	50                   	push   %eax
 8048641:	e8 2a fe ff ff       	call   8048470 <puts@plt>
 8048646:	83 c4 10             	add    $0x10,%esp
 8048649:	8b 4d f4             	mov    -0xc(%ebp),%ecx
 804864c:	65 33 0d 14 00 00 00 	xor    %gs:0x14,%ecx
 8048653:	74 05                	je     804865a <dovuln+0x8f>
 8048655:	e8 06 fe ff ff       	call   8048460 <__stack_chk_fail@plt>
 804865a:	c9                   	leave  
 804865b:	c3                   	ret    

0804865c <main>:
 804865c:	8d 4c 24 04          	lea    0x4(%esp),%ecx
 8048660:	83 e4 f0             	and    $0xfffffff0,%esp
 8048663:	ff 71 fc             	pushl  -0x4(%ecx)
 8048666:	55                   	push   %ebp
 8048667:	89 e5                	mov    %esp,%ebp
 8048669:	51                   	push   %ecx
 804866a:	83 ec 04             	sub    $0x4,%esp
 804866d:	a1 80 a0 04 08       	mov    0x804a080,%eax
 8048672:	83 ec 08             	sub    $0x8,%esp
 8048675:	6a 00                	push   $0x0
 8048677:	50                   	push   %eax
 8048678:	e8 c3 fd ff ff       	call   8048440 <setbuf@plt>
 804867d:	83 c4 10             	add    $0x10,%esp
 8048680:	a1 84 a0 04 08       	mov    0x804a084,%eax
 8048685:	83 ec 08             	sub    $0x8,%esp
 8048688:	6a 00                	push   $0x0
 804868a:	50                   	push   %eax
 804868b:	e8 b0 fd ff ff       	call   8048440 <setbuf@plt>
 8048690:	83 c4 10             	add    $0x10,%esp
 8048693:	a1 60 a0 04 08       	mov    0x804a060,%eax
 8048698:	83 ec 08             	sub    $0x8,%esp
 804869b:	6a 00                	push   $0x0
 804869d:	50                   	push   %eax
 804869e:	e8 9d fd ff ff       	call   8048440 <setbuf@plt>
 80486a3:	83 c4 10             	add    $0x10,%esp
 80486a6:	83 ec 04             	sub    $0x4,%esp
 80486a9:	6a 1e                	push   $0x1e
 80486ab:	68 38 a0 04 08       	push   $0x804a038
 80486b0:	6a 01                	push   $0x1
 80486b2:	e8 f9 fd ff ff       	call   80484b0 <write@plt>
 80486b7:	83 c4 10             	add    $0x10,%esp
 80486ba:	e8 0c ff ff ff       	call   80485cb <dovuln>
 80486bf:	b8 00 00 00 00       	mov    $0x0,%eax
 80486c4:	8b 4d fc             	mov    -0x4(%ebp),%ecx
 80486c7:	c9                   	leave  
 80486c8:	8d 61 fc             	lea    -0x4(%ecx),%esp
 80486cb:	c3                   	ret    
 80486cc:	66 90                	xchg   %ax,%ax
 80486ce:	66 90                	xchg   %ax,%ax

080486d0 <__libc_csu_init>:
 80486d0:	55                   	push   %ebp
 80486d1:	57                   	push   %edi
 80486d2:	31 ff                	xor    %edi,%edi
 80486d4:	56                   	push   %esi
 80486d5:	53                   	push   %ebx
 80486d6:	e8 25 fe ff ff       	call   8048500 <__x86.get_pc_thunk.bx>
 80486db:	81 c3 25 19 00 00    	add    $0x1925,%ebx
 80486e1:	83 ec 0c             	sub    $0xc,%esp
 80486e4:	8b 6c 24 20          	mov    0x20(%esp),%ebp
 80486e8:	8d b3 0c ff ff ff    	lea    -0xf4(%ebx),%esi
 80486ee:	e8 15 fd ff ff       	call   8048408 <_init>
 80486f3:	8d 83 08 ff ff ff    	lea    -0xf8(%ebx),%eax
 80486f9:	29 c6                	sub    %eax,%esi
 80486fb:	c1 fe 02             	sar    $0x2,%esi
 80486fe:	85 f6                	test   %esi,%esi
 8048700:	74 23                	je     8048725 <__libc_csu_init+0x55>
 8048702:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
 8048708:	83 ec 04             	sub    $0x4,%esp
 804870b:	ff 74 24 2c          	pushl  0x2c(%esp)
 804870f:	ff 74 24 2c          	pushl  0x2c(%esp)
 8048713:	55                   	push   %ebp
 8048714:	ff 94 bb 08 ff ff ff 	call   *-0xf8(%ebx,%edi,4)
 804871b:	83 c7 01             	add    $0x1,%edi
 804871e:	83 c4 10             	add    $0x10,%esp
 8048721:	39 f7                	cmp    %esi,%edi
 8048723:	75 e3                	jne    8048708 <__libc_csu_init+0x38>
 8048725:	83 c4 0c             	add    $0xc,%esp
 8048728:	5b                   	pop    %ebx
 8048729:	5e                   	pop    %esi
 804872a:	5f                   	pop    %edi
 804872b:	5d                   	pop    %ebp
 804872c:	c3                   	ret    
 804872d:	8d 76 00             	lea    0x0(%esi),%esi

08048730 <__libc_csu_fini>:
 8048730:	f3 c3                	repz ret 

Disassembly of section .fini:

08048734 <_fini>:
 8048734:	53                   	push   %ebx
 8048735:	83 ec 08             	sub    $0x8,%esp
 8048738:	e8 c3 fd ff ff       	call   8048500 <__x86.get_pc_thunk.bx>
 804873d:	81 c3 c3 18 00 00    	add    $0x18c3,%ebx
 8048743:	83 c4 08             	add    $0x8,%esp
 8048746:	5b                   	pop    %ebx
 8048747:	c3                   	ret    
