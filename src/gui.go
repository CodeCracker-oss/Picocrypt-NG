package main

/*

Picocrypt NG v2.00
Copyright (c) Picocrypt NG developers
Released under GPL-3.0-only
https://github.com/Picocrypt-NG/Picocrypt-NG

~ In cryptography we trust ~

*/

import (
	"crypto/rand"
	"errors"
	"fmt"
	"image"
	"image/color"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gioui.org/app"
	"gioui.org/font/gofont"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/Picocrypt/zxcvbn-go"
	"github.com/ncruces/zenity"
)

const (
	ViewStart = iota
	ViewEncrypt
	ViewGenerate
	ViewOrder
	ViewDecrypt
	ViewProgress
)

var (
	currentView = ViewStart

	selectFiles    = new(widget.Clickable)
	passEditor     = &widget.Editor{SingleLine: true}
	confirmEditor  = &widget.Editor{SingleLine: true}
	toggleHide     = new(widget.Clickable)
	hidePass       = true
	generateBtn    = new(widget.Clickable)
	editKeyfiles   = new(widget.Clickable)
	createKeyfiles = new(widget.Clickable)
	orderKeyfiles  = new(widget.Clickable)

	commentsEditor  = &widget.Editor{SingleLine: false}
	paranoidChk     = new(widget.Bool)
	compressChk     = new(widget.Bool)
	rsChk           = new(widget.Bool)
	deleteChk       = new(widget.Bool)
	deniabilityChk  = new(widget.Bool)
	recursiveChk    = new(widget.Bool)
	splitChk        = new(widget.Bool)
	splitEditor     = &widget.Editor{SingleLine: true}
	splitCycleBtn   = new(widget.Clickable)
	splitCycleIndex = 0
	changeBtn       = new(widget.Clickable)
	requireOrder    = new(widget.Bool)
	clearBtn        = new(widget.Clickable)
	startBtn        = new(widget.Clickable)

	forceDecryptChk = new(widget.Bool)
	deleteVolumeChk = new(widget.Bool)
	autoUnzipChk    = new(widget.Bool)
	sameLevelChk    = new(widget.Bool)

	uppercase = new(widget.Bool)
	lowercase = new(widget.Bool)
	numbers   = new(widget.Bool)
	symbols   = new(widget.Bool)

	progressPct float32 = 0.0
	progressMsg string  = ""
)

var (
	colFg         = color.NRGBA{R: 0xee, G: 0xee, B: 0xee, A: 0xff}
	colContrastFg = color.NRGBA{R: 0x12, G: 0x12, B: 0x12, A: 0xff}
	colBg         = color.NRGBA{R: 0x26, G: 0x32, B: 0x38, A: 0xff}
	colPrimary    = color.NRGBA{R: 0x00, G: 0x96, B: 0x88, A: 0xff}
	colSecondary  = color.NRGBA{R: 0x7c, G: 0x4d, B: 0xff, A: 0xff}
	colSurface    = color.NRGBA{R: 0x33, G: 0x3e, B: 0x45, A: 0xff}
	colSurfaceAlt = color.NRGBA{R: 0x2b, G: 0x36, B: 0x3c, A: 0xff}
	colHint       = color.NRGBA{R: 0x9e, G: 0xa0, B: 0xa4, A: 0xff}
)

var (
	orderWorking []string
	orderUps     []*widget.Clickable
	orderDowns   []*widget.Clickable
	orderRemoves []*widget.Clickable
	orderDone    = new(widget.Clickable)
	orderCancel  = new(widget.Clickable)
	orderInited  bool
)

var (
	minusGenerate  = new(widget.Clickable)
	plusGenerate   = new(widget.Clickable)
	genBtnGenerate = new(widget.Clickable)
)

var lengthVal = 16

var passwordScore int = 0

func scoreToProgress(score int) float32 {
	if score < 0 {
		score = 0
	}
	if score > 4 {
		score = 4
	}
	return float32(score) / 4.0
}

var mu sync.Mutex

var startList = &widget.List{List: layout.List{Axis: layout.Vertical}}
var encryptList = &widget.List{List: layout.List{Axis: layout.Vertical}}
var generateList = &widget.List{List: layout.List{Axis: layout.Vertical}}
var decryptList = &widget.List{List: layout.List{Axis: layout.Vertical}}
var progressList = &widget.List{List: layout.List{Axis: layout.Vertical}}

func main() {
	passEditor.Mask = '*'
	confirmEditor.Mask = '*'

	state.outputFile = ""
	status.progress = 0
	status.progressInfo = ""
	state.keyfileOrdered = false

	go func() {
		w := new(app.Window)
		w.Option(app.Size(unit.Dp(650), unit.Dp(700)))
		w.Option(app.Title("Picocrypt NG"))
		if err := run(w); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}()
	app.Main()
}

func run(w *app.Window) error {
	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.WithCollection(gofont.Collection()))

	var ops op.Ops
	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			return e.Err
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)

			syncStateToWidgets()

			cs := gtx.Constraints.Max
			paintFill(gtx, colBg, imageRect(cs.X, cs.Y))

			switch currentView {
			case ViewStart:
				layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					maxW := gtx.Dp(unit.Dp(600))
					if gtx.Constraints.Max.X > maxW {
						gtx.Constraints.Max.X = maxW
					}

					return material.List(th, startList).Layout(gtx, 1, func(gtx layout.Context, index int) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								lbl := material.Body1(th, "Select file(s) to encrypt or a volume to decrypt")
								lbl.Color = colFg
								return layout.Inset{Bottom: unit.Dp(16)}.Layout(gtx, lbl.Layout)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								for selectFiles.Clicked(gtx) {
									files, err := zenity.SelectFileMultiple(
										zenity.Filename(""),
									)
									if err != nil {
										if err == zenity.ErrCanceled {
											continue
										}
										log.Fatalf("dialog error: %v", err)
									}
									onDrop(files)
									if state.mode == "encrypt" {
										currentView = ViewEncrypt
									} else {
										currentView = ViewDecrypt
									}
								}
								btn := material.Button(th, selectFiles, "Select file(s)")
								btn.Background = colPrimary
								btn.Color = colContrastFg
								return btn.Layout(gtx)
							}),
						)
					})
				})

			case ViewEncrypt:
				layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					maxW := gtx.Dp(unit.Dp(600))
					if gtx.Constraints.Max.X > maxW {
						gtx.Constraints.Max.X = maxW
					}

					passwordHeader := func(gtx layout.Context) layout.Dimensions {
						toggleWidth := gtx.Dp(unit.Dp(72))
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								gtx.Constraints.Min.X = toggleWidth
								gtx.Constraints.Max.X = toggleWidth
								for toggleHide.Clicked(gtx) {
									hidePass = !hidePass
									if hidePass {
										passEditor.Mask = '*'
										confirmEditor.Mask = '*'
									} else {
										passEditor.Mask = 0
										confirmEditor.Mask = 0
									}
								}
								label := "Show"
								if !hidePass {
									label = "Hide"
								}
								btn := material.Button(th, toggleHide, label)
								btn.Background = colSecondary
								btn.Color = colContrastFg
								return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(4), Bottom: unit.Dp(8)}.Layout(gtx, btn.Layout)
							}),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									lbl := material.Body1(th, "Password")
									lbl.Color = colFg
									return layout.Inset{Bottom: unit.Dp(8)}.Layout(gtx, lbl.Layout)
								})
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								for generateBtn.Clicked(gtx) {
									currentView = ViewGenerate
								}
								btn := material.Button(th, generateBtn, "Generate")
								btn.Background = colPrimary
								btn.Color = colContrastFg
								return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(4), Bottom: unit.Dp(8)}.Layout(gtx, btn.Layout)
							}),
						)
					}

					return material.List(th, encryptList).Layout(gtx, 1, func(gtx layout.Context, index int) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								h := material.H4(th, "Encrypt")
								h.Color = colFg
								return layout.Inset{Bottom: unit.Dp(20)}.Layout(gtx, h.Layout)
							}),
							layout.Rigid(passwordHeader),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								pw := passEditor.Text()
								score := 0
								if pw != "" {
									score = zxcvbn.PasswordStrength(pw, nil).Score
								}
								passwordScore = score
								progress := scoreToProgress(score)

								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										gtx.Constraints.Min.X = gtx.Constraints.Max.X
										h := gtx.Dp(unit.Dp(40))
										gtx.Constraints.Min.Y = h
										gtx.Constraints.Max.Y = h
										return layout.UniformInset(unit.Dp(4)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											rect := imageRect(gtx.Constraints.Max.X, h)
											paintFill(gtx, colSurface, rect)
											e := material.Editor(th, passEditor, "")
											e.Color = colFg
											e.HintColor = colHint
											return e.Layout(gtx)
										})
									}),

									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										size := gtx.Dp(unit.Dp(36))
										gtx.Constraints.Min.X = size
										gtx.Constraints.Max.X = size
										gtx.Constraints.Min.Y = size
										gtx.Constraints.Max.Y = size

										return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											return material.ProgressCircle(th, progress).Layout(gtx)
										})
									}),
								)
							}),

							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Spacer{Height: unit.Dp(12)}.Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								pw := passEditor.Text()
								confirm := confirmEditor.Text()
								match := (pw != "" && pw == confirm)

								var matchProgress float32
								if match {
									matchProgress = 1.0
								} else {
									matchProgress = 0.0
								}

								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										gtx.Constraints.Min.X = gtx.Constraints.Max.X
										h := gtx.Dp(unit.Dp(40))
										gtx.Constraints.Min.Y = h
										gtx.Constraints.Max.Y = h
										return layout.UniformInset(unit.Dp(4)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											rect := imageRect(gtx.Constraints.Max.X, h)
											paintFill(gtx, colSurface, rect)
											e := material.Editor(th, confirmEditor, "")
											e.Color = colFg
											e.HintColor = colHint
											return e.Layout(gtx)
										})
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										size := gtx.Dp(unit.Dp(36))
										gtx.Constraints.Min.X = size
										gtx.Constraints.Max.X = size
										gtx.Constraints.Min.Y = size
										gtx.Constraints.Max.Y = size

										return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											return material.ProgressCircle(th, matchProgress).Layout(gtx)
										})
									}),
								)
							}),

							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														return layout.Inset{Left: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
															lbl := material.Body1(th, "Keyfiles")
															lbl.Color = colFg
															return layout.Inset{Right: unit.Dp(12)}.Layout(gtx, lbl.Layout)
														})
													}),
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														cb := material.CheckBox(th, requireOrder, "Require correct order")
														cb.Color = colFg
														return layout.Inset{Right: unit.Dp(12)}.Layout(gtx, cb.Layout)
													}),
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														for orderKeyfiles.Clicked(gtx) {
															currentView = ViewOrder
														}

														btn := material.Button(th, orderKeyfiles, "Order keyfiles")
														btn.Background = colSurface
														btn.Color = colFg
														return layout.Inset{Right: unit.Dp(8)}.Layout(gtx, btn.Layout)
													}),
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														for editKeyfiles.Clicked(gtx) {
															defPath := ""
															paths, err := zenity.SelectFileMultiple(
																zenity.Filename(defPath),
																zenity.FileFilter{"All files", []string{"*"}, true},
															)
															if err != nil {
																if err == zenity.ErrCanceled {
																	continue
																}
																status.main = "Failed to open file chooser"
																status.mainColor = RED
																continue
															}

															state.keyfiles = append([]string(nil), paths...)
															orderWorking = append([]string(nil), state.keyfiles...)

															if len(state.keyfiles) == 0 {
																status.keyfileLabel = "None selected"
															} else if len(state.keyfiles) == 1 {
																status.keyfileLabel = "Using 1 keyfile"
															} else {
																status.keyfileLabel = fmt.Sprintf("Using %d keyfiles", len(state.keyfiles))
															}

															orderUps = nil
															orderDowns = nil
															orderRemoves = nil
															orderInited = false
														}

														btn := material.Button(th, editKeyfiles, "Edit")
														btn.Background = colSurface
														btn.Color = colFg
														return layout.Inset{Right: unit.Dp(8)}.Layout(gtx, btn.Layout)
													}),
													layout.Rigid(func(gtx layout.Context) layout.Dimensions {
														for createKeyfiles.Clicked(gtx) {
															defName := "keyfile-" + strconv.Itoa(int(time.Now().Unix())) + ".bin"

															file, err := zenity.SelectFileSave(
																zenity.Filename(defName),
																zenity.ConfirmOverwrite(),
															)
															if err != nil {
																if err == zenity.ErrCanceled {
																	continue
																}
																status.main = "Failed to open save dialog"
																status.mainColor = RED
																continue
															}
															if file == "" {
																continue
															}

															fout, err := os.Create(file)
															if err != nil {
																status.main = "Failed to create keyfile"
																status.mainColor = RED
																continue
															}

															data := make([]byte, 32)
															if n, err := rand.Read(data); err != nil || n != 32 {
																fout.Close()
																panic(errors.New("fatal crypto/rand error"))
															}

															if n, err := fout.Write(data); err != nil || n != 32 {
																fout.Close()
																panic(errors.New("failed to write full keyfile"))
															}

															if err := fout.Close(); err != nil {
																panic(err)
															}

															status.main = "Ready"
															status.mainColor = WHITE
														}

														btn := material.Button(th, createKeyfiles, "Create")
														btn.Background = colPrimary
														btn.Color = colContrastFg
														return btn.Layout(gtx)
													}),
													layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
														h := gtx.Dp(unit.Dp(36))
														gtx.Constraints.Min.Y = h
														gtx.Constraints.Max.Y = h
														rect := imageRect(gtx.Constraints.Max.X, h)
														paintFill(gtx, colSurfaceAlt, rect)
														lbl := material.Body2(th, status.keyfileLabel)
														lbl.Color = colHint
														return layout.Inset{Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx, lbl.Layout)
													}),
												)
											}),
										)
									}),
								)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								lbl := material.Body1(th, "Comments")
								lbl.Color = colFg
								return layout.Inset{Left: unit.Dp(4), Top: unit.Dp(12), Bottom: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return lbl.Layout(gtx)
								})
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								h := gtx.Dp(unit.Dp(120))
								gtx.Constraints.Min.X = gtx.Constraints.Max.X
								gtx.Constraints.Min.Y = h
								gtx.Constraints.Max.Y = h
								return layout.UniformInset(unit.Dp(4)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									rect := imageRect(gtx.Constraints.Max.X, h)
									paintFill(gtx, colSurface, rect)

									e := material.Editor(th, commentsEditor, "")
									e.Color = colFg
									e.Hint = "Note: comments are not encrypted!"
									e.HintColor = colHint
									return e.Layout(gtx)
								})
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								lbl := material.Body1(th, "Advanced")
								lbl.Color = colFg
								return layout.Inset{Left: unit.Dp(4), Top: unit.Dp(12), Bottom: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return lbl.Layout(gtx)
								})
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								for splitCycleBtn.Clicked(gtx) {
									splitCycleIndex = (splitCycleIndex + 1) % 4
								}

								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												cb := material.CheckBox(th, paranoidChk, "Paranoid mode")
												cb.Color = colFg
												return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(12)}.Layout(gtx, cb.Layout)
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												cb := material.CheckBox(th, compressChk, "Compress files")
												cb.Color = colFg
												return layout.Inset{Right: unit.Dp(12)}.Layout(gtx, cb.Layout)
											}),
										)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												cb := material.CheckBox(th, rsChk, "Reed-Solomon")
												cb.Color = colFg
												return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(12)}.Layout(gtx, cb.Layout)
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												cb := material.CheckBox(th, deleteChk, "Delete files")
												cb.Color = colFg
												return layout.Inset{Right: unit.Dp(12)}.Layout(gtx, cb.Layout)
											}),
										)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												cb := material.CheckBox(th, deniabilityChk, "Deniability")
												cb.Color = colFg
												return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(12)}.Layout(gtx, cb.Layout)
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												cb := material.CheckBox(th, recursiveChk, "Recursively")
												cb.Color = colFg
												return layout.Inset{Right: unit.Dp(12)}.Layout(gtx, cb.Layout)
											}),
										)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												cb := material.CheckBox(th, splitChk, "Split into chunks")
												cb.Color = colFg
												return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(8)}.Layout(gtx, cb.Layout)
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												w := gtx.Dp(unit.Dp(80))
												h := gtx.Dp(unit.Dp(36))
												gtx.Constraints.Min.X = w
												gtx.Constraints.Max.X = w
												gtx.Constraints.Min.Y = h
												gtx.Constraints.Max.Y = h

												txt := splitEditor.Text()
												filtered := make([]rune, 0, len(txt))
												for _, r := range txt {
													if r >= '0' && r <= '9' {
														filtered = append(filtered, r)
													}
												}
												if string(filtered) != txt {
													splitEditor.SetText(string(filtered))
												}

												return layout.Inset{Right: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
													rect := imageRect(gtx.Constraints.Max.X, h)
													paintFill(gtx, colSurface, rect)
													e := material.Editor(th, splitEditor, "")
													e.Color = colFg
													e.Hint = "0"
													e.HintColor = colHint
													return e.Layout(gtx)
												})
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												w := gtx.Dp(unit.Dp(56))
												h := gtx.Dp(unit.Dp(36))
												gtx.Constraints.Min.X = w
												gtx.Constraints.Max.X = w
												gtx.Constraints.Min.Y = h
												gtx.Constraints.Max.Y = h

												label := splitUnits[splitCycleIndex]
												btn := material.Button(th, splitCycleBtn, label)
												btn.Background = colSecondary
												btn.Color = colContrastFg
												return btn.Layout(gtx)
											}),
										)
									}),
								)
							}),

							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										lbl := material.Body1(th, "Save output as")
										lbl.Color = colFg
										return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(12)}.Layout(gtx, lbl.Layout)
									}),
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
											layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
												h := gtx.Dp(unit.Dp(36))
												gtx.Constraints.Min.Y = h
												gtx.Constraints.Max.Y = h

												availW := gtx.Constraints.Max.X
												child := gtx
												child.Constraints.Min.X = 0
												child.Constraints.Max.X = availW

												rect := imageRect(availW, h)
												paintFill(child, colSurface, rect)

												lbl := material.Body2(th, state.outputFile)
												lbl.Color = colFg
												return layout.Inset{Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx, lbl.Layout)
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												w := gtx.Dp(unit.Dp(92))
												h := gtx.Dp(unit.Dp(36))
												gtx.Constraints.Min.X = w
												gtx.Constraints.Max.X = w
												gtx.Constraints.Min.Y = h
												gtx.Constraints.Max.Y = h

												for changeBtn.Clicked(gtx) {
													startDir := ""
													if len(state.onlyFiles) > 0 {
														startDir = filepath.Dir(state.onlyFiles[0])
													} else if len(state.onlyFolders) > 0 {
														startDir = filepath.Dir(state.onlyFolders[0])
													}

													tmp := strings.TrimSuffix(filepath.Base(state.outputFile), ".pcv")
													initName := strings.TrimSuffix(tmp, filepath.Ext(tmp))
													if state.mode == "encrypt" && (len(state.allFiles) > 1 || len(state.onlyFolders) > 0 || state.compress) {
														initName = "encrypted-" + strconv.Itoa(int(time.Now().Unix()))
													}

													options := []zenity.Option{
														zenity.Filename(initName),
														zenity.ConfirmOverwrite(),
													}
													if startDir != "" {
														prevDir, _ := os.Getwd()
														_ = os.Chdir(startDir)
														defer os.Chdir(prevDir)
													}

													file, err := zenity.SelectFileSave(options...)
													if err != nil {
														if err == zenity.ErrCanceled {
															continue
														}
														status.main = "Failed to open save dialog"
														status.mainColor = RED
														continue
													}
													if file == "" {
														continue
													}

													base := strings.Split(filepath.Base(file), ".")[0]
													file = filepath.Join(filepath.Dir(file), base)

													if state.mode == "encrypt" {
														if len(state.allFiles) > 1 || len(state.onlyFolders) > 0 || state.compress {
															file += ".zip.pcv"
														} else {
															file += filepath.Ext(state.inputFile) + ".pcv"
														}
													} else {
														if strings.HasSuffix(state.inputFile, ".zip.pcv") {
															file += ".zip"
														} else {
															tmp2 := strings.TrimSuffix(filepath.Base(state.inputFile), ".pcv")
															file += filepath.Ext(tmp2)
														}
													}

													state.outputFile = file
													status.main = "Ready"
													status.mainColor = WHITE
												}
												btn := material.Button(th, changeBtn, "Change")
												btn.Background = colSecondary
												btn.Color = colContrastFg
												return btn.Layout(gtx)
											}),
										)
									}),
								)

							}),

							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								sideW := gtx.Dp(unit.Dp(92))
								btnH := gtx.Dp(unit.Dp(40))

								backClickable := selectFiles

								for backClickable.Clicked(gtx) {
									currentView = ViewStart
								}
								for clearBtn.Clicked(gtx) {
									save := state.outputFile
									state = WorkOptions{}
									state.outputFile = save
									passEditor.SetText("")
									confirmEditor.SetText("")
									commentsEditor.SetText("")
									splitEditor.SetText("")
									paranoidChk.Value = false
									compressChk.Value = false
									rsChk.Value = false
									deleteChk.Value = false
									deniabilityChk.Value = false
									recursiveChk.Value = false
									splitChk.Value = false
									if requireOrder != nil {
										requireOrder.Value = false
									}
									hidePass = true
									passEditor.Mask = '*'
									confirmEditor.Mask = '*'
									splitCycleIndex = 0
								}
								for startBtn.Clicked(gtx) {
									syncWidgetsToState()
									mu.Lock()
									status.working = true
									status.showProgress = true
									status.progress = 0
									status.progressInfo = "Starting..."
									mu.Unlock()

									// Start button should be disabled if these conditions are true; don't do anything if so
									if (len(state.keyfiles) == 0 && state.password == "") || (state.mode == "encrypt" && state.password != state.confirmPassword) {
										continue
									}

									if state.keyfile && state.keyfiles == nil {
										status.main = "Please select your keyfiles"
										status.mainColor = RED
										continue
									}
									tmp, err := strconv.Atoi(state.splitSize)
									if state.split && (state.splitSize == "" || err != nil || tmp <= 0) {
										status.main = "Invalid chunk size"
										status.mainColor = RED
										continue
									}

									// Check if output file already exists
									_, err = os.Stat(state.outputFile)

									// Check if any split chunks already exist
									if state.split {
										names, err2 := filepath.Glob(state.outputFile + ".*")
										if err2 != nil {
											panic(err2)
										}
										if len(names) > 0 {
											err = nil
										} else {
											err = os.ErrNotExist
										}
									}

									// If files already exist, show the overwrite modal
									if err == nil && !state.recursively {
										ok := zenity.Question("Outputfile already exists. Overwrite?",
											zenity.Title("Question"),
											zenity.QuestionIcon,
										)
										if ok != nil {
											continue
										}
									}
									status.showProgress = true
									fastDecode = true
									status.canCancel = true
									currentView = ViewProgress
									if !state.recursively {
										go func() {
											work()
											status.working = false
											status.showProgress = false
											currentView = ViewStart

										}()
									} else {
										// Store variables as they will be cleared
										oldPassword := state.password
										oldKeyfile := state.keyfile
										oldKeyfiles := state.keyfiles
										oldKeyfileOrdered := state.keyfileOrdered
										oldKeyfileLabel := status.keyfileLabel
										oldComments := state.comments
										oldParanoid := state.paranoid
										oldReedsolo := state.reedSolomon
										oldDeniability := state.deniability
										oldSplit := state.split
										oldSplitSize := state.splitSize
										oldSplitSelected := state.splitSelected
										oldDelete := state.delete
										files := state.allFiles
										go func() {
											for _, file := range files {
												// Simulate dropping the file
												onDrop([]string{file})

												// Restore variables and options
												state.password = oldPassword
												state.confirmPassword = oldPassword
												state.keyfile = oldKeyfile
												state.keyfiles = oldKeyfiles
												state.keyfileOrdered = oldKeyfileOrdered
												status.keyfileLabel = oldKeyfileLabel
												state.comments = oldComments
												state.paranoid = oldParanoid
												state.reedSolomon = oldReedsolo
												if state.mode != "decrypt" {
													state.deniability = oldDeniability
												}
												state.split = oldSplit
												state.splitSize = oldSplitSize
												state.splitSelected = oldSplitSelected
												state.delete = oldDelete

												work()
												if !status.working {
													resetUI()
													cancel(nil, nil)
													status.showProgress = false
													currentView = ViewStart
													continue
												}
											}
											status.working = false
											status.showProgress = false
											currentView = ViewStart
											w.Invalidate()
										}()
									}
								}

								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										gtx.Constraints.Min.X = sideW
										gtx.Constraints.Max.X = sideW
										gtx.Constraints.Min.Y = btnH
										gtx.Constraints.Max.Y = btnH
										btn := material.Button(th, backClickable, "Back")
										btn.Background = colPrimary
										btn.Color = colContrastFg
										return layout.Inset{Left: unit.Dp(8)}.Layout(gtx, btn.Layout)
									}),
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											w := gtx.Dp(unit.Dp(160))
											h := gtx.Dp(unit.Dp(52))
											gtx.Constraints.Min.X = w
											gtx.Constraints.Max.X = w
											gtx.Constraints.Min.Y = h
											gtx.Constraints.Max.Y = h
											btn := material.Button(th, startBtn, "Start")
											btn.Background = colPrimary
											btn.Color = colContrastFg
											return btn.Layout(gtx)
										})
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										gtx.Constraints.Min.X = sideW
										gtx.Constraints.Max.X = sideW
										gtx.Constraints.Min.Y = btnH
										gtx.Constraints.Max.Y = btnH
										btn := material.Button(th, clearBtn, "Clear")
										btn.Background = colSurface
										btn.Color = colHint
										return layout.Inset{Right: unit.Dp(8)}.Layout(gtx, btn.Layout)
									}),
								)
							}),
						)
					})
				})

			case ViewGenerate:
				layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					maxW := gtx.Dp(unit.Dp(600))
					if gtx.Constraints.Max.X > maxW {
						gtx.Constraints.Max.X = maxW
					}

					lengthStr := strconv.Itoa(lengthVal)

					passwordHeader := func(gtx layout.Context) layout.Dimensions {
						toggleWidth := gtx.Dp(unit.Dp(72))
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								gtx.Constraints.Min.X = toggleWidth
								gtx.Constraints.Max.X = toggleWidth
								for toggleHide.Clicked(gtx) {
									hidePass = !hidePass
									if hidePass {
										passEditor.Mask = '*'
										confirmEditor.Mask = '*'
									} else {
										passEditor.Mask = 0
										confirmEditor.Mask = 0
									}
								}
								label := "Show"
								if !hidePass {
									label = "Hide"
								}
								btn := material.Button(th, toggleHide, label)
								btn.Background = colSecondary
								btn.Color = colContrastFg
								return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(4), Bottom: unit.Dp(8)}.Layout(gtx, btn.Layout)
							}),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									lbl := material.Body1(th, "Generated password")
									lbl.Color = colFg
									return layout.Inset{Bottom: unit.Dp(8)}.Layout(gtx, lbl.Layout)
								})
							}),
						)
					}

					return material.List(th, generateList).Layout(gtx, 1, func(gtx layout.Context, index int) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								h := material.H4(th, "Generate password")
								h.Color = colFg
								return layout.Inset{Bottom: unit.Dp(20)}.Layout(gtx, h.Layout)
							}),

							layout.Rigid(passwordHeader),

							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								h := gtx.Dp(unit.Dp(40))
								gtx.Constraints.Min.X = gtx.Constraints.Max.X
								gtx.Constraints.Min.Y = h
								gtx.Constraints.Max.Y = h
								return layout.UniformInset(unit.Dp(4)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									rect := imageRect(gtx.Constraints.Max.X, h)
									paintFill(gtx, colSurface, rect)
									e := material.Editor(th, passEditor, "")
									e.Color = colFg
									e.HintColor = colHint
									if hidePass {
										passEditor.Mask = '*'
									} else {
										passEditor.Mask = 0
									}
									return e.Layout(gtx)
								})
							}),

							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Spacer{Height: unit.Dp(12)}.Layout(gtx)
							}),

							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										lbl := material.Body1(th, "Length")
										lbl.Color = colFg
										return layout.Inset{Left: unit.Dp(4), Bottom: unit.Dp(8)}.Layout(gtx, lbl.Layout)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												w := gtx.Dp(unit.Dp(50))
												h := gtx.Dp(unit.Dp(36))
												gtx.Constraints.Min.X = w
												gtx.Constraints.Max.X = w
												gtx.Constraints.Min.Y = h
												gtx.Constraints.Max.Y = h
												for minusGenerate.Clicked(gtx) {
													if lengthVal > 12 {
														lengthVal--
														lengthStr = strconv.Itoa(lengthVal)
													}
												}
												btn := material.Button(th, minusGenerate, "-")
												btn.Background = colSurfaceAlt
												btn.Color = colFg
												return layout.Inset{Right: unit.Dp(8)}.Layout(gtx, btn.Layout)
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												w := gtx.Dp(unit.Dp(72))
												h := gtx.Dp(unit.Dp(36))
												gtx.Constraints.Min.X = w
												gtx.Constraints.Max.X = w
												gtx.Constraints.Min.Y = h
												gtx.Constraints.Max.Y = h
												rect := imageRect(gtx.Constraints.Max.X, h)
												paintFill(gtx, colSurface, rect)
												lbl := material.Body1(th, lengthStr)
												lbl.Color = colFg
												return layout.Inset{Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx, lbl.Layout)
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												w := gtx.Dp(unit.Dp(50))
												h := gtx.Dp(unit.Dp(36))
												gtx.Constraints.Min.X = w
												gtx.Constraints.Max.X = w
												gtx.Constraints.Min.Y = h
												gtx.Constraints.Max.Y = h
												for plusGenerate.Clicked(gtx) {
													if lengthVal < 64 {
														lengthVal++
														lengthStr = strconv.Itoa(lengthVal)
													}
												}
												btn := material.Button(th, plusGenerate, "+")
												btn.Background = colSurfaceAlt
												btn.Color = colFg
												return layout.Inset{Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx, btn.Layout)
											}),
											layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
												h := gtx.Dp(unit.Dp(8))
												w := gtx.Constraints.Max.X
												gtx.Constraints.Min.Y = h
												gtx.Constraints.Max.Y = h
												rect := imageRect(w, h)
												paintFill(gtx, colSurfaceAlt, rect)
												t := float32(lengthVal-12) / float32(64-12)
												fw := int(float32(w) * t)
												filled := imageRect(fw, h)
												paintFill(gtx, colPrimary, filled)
												return layout.Dimensions{Size: image.Point{X: w, Y: h}}
											}),
										)
									}),
								)
							}),

							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Spacer{Height: unit.Dp(12)}.Layout(gtx)
							}),

							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										cb := material.CheckBox(th, uppercase, "Uppercase")
										cb.Color = colFg
										return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(12)}.Layout(gtx, cb.Layout)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										cb := material.CheckBox(th, lowercase, "Lowercase")
										cb.Color = colFg
										return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(12)}.Layout(gtx, cb.Layout)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										cb := material.CheckBox(th, numbers, "Numbers")
										cb.Color = colFg
										return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(12)}.Layout(gtx, cb.Layout)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										cb := material.CheckBox(th, symbols, "Symbols")
										cb.Color = colFg
										return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(12)}.Layout(gtx, cb.Layout)
									}),
								)
							}),

							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Spacer{Height: unit.Dp(12)}.Layout(gtx)
							}),

							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								sideW := gtx.Dp(unit.Dp(92))
								btnH := gtx.Dp(unit.Dp(40))

								backClickable := selectFiles

								for backClickable.Clicked(gtx) {
									currentView = ViewEncrypt
								}
								for genBtnGenerate.Clicked(gtx) {
									syncWidgetsToState()
									if !(uppercase.Value || lowercase.Value || numbers.Value || symbols.Value) {
										status.main = "Select at least one character set"
										status.mainColor = RED
										continue
									}
									pass := genPassword()
									state.password = pass
									state.confirmPassword = pass
									passEditor.SetText(pass)
									confirmEditor.SetText(pass)
									status.main = "Generated"
									status.mainColor = GREEN
								}

								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										gtx.Constraints.Min.X = sideW
										gtx.Constraints.Max.X = sideW
										gtx.Constraints.Min.Y = btnH
										gtx.Constraints.Max.Y = btnH
										btn := material.Button(th, backClickable, "Back")
										btn.Background = colPrimary
										btn.Color = colContrastFg
										return layout.Inset{Left: unit.Dp(8)}.Layout(gtx, btn.Layout)
									}),
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											w := gtx.Dp(unit.Dp(160))
											h := gtx.Dp(unit.Dp(52))
											gtx.Constraints.Min.X = w
											gtx.Constraints.Max.X = w
											gtx.Constraints.Min.Y = h
											gtx.Constraints.Max.Y = h
											btn := material.Button(th, genBtnGenerate, "Generate")
											btn.Background = colPrimary
											btn.Color = colContrastFg
											return btn.Layout(gtx)
										})
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										gtx.Constraints.Min.X = sideW
										gtx.Constraints.Max.X = sideW
										gtx.Constraints.Min.Y = btnH
										gtx.Constraints.Max.Y = btnH
										return layout.Dimensions{Size: image.Point{X: sideW, Y: btnH}}
									}),
								)
							}),
						)
					})
				})

			case ViewOrder:
				layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							maxW := gtx.Dp(unit.Dp(700))
							if gtx.Constraints.Max.X > maxW {
								gtx.Constraints.Max.X = maxW
							}

							if !orderInited {
								orderWorking = append([]string(nil), state.keyfiles...)
								n := len(orderWorking)
								orderUps = make([]*widget.Clickable, n)
								orderDowns = make([]*widget.Clickable, n)
								orderRemoves = make([]*widget.Clickable, n)
								for i := 0; i < n; i++ {
									orderUps[i] = new(widget.Clickable)
									orderDowns[i] = new(widget.Clickable)
									orderRemoves[i] = new(widget.Clickable)
								}
								orderInited = true
							}

							return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Inset{Bottom: unit.Dp(12)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											header := material.H5(th, "Order keyfiles")
											header.Color = colFg
											return header.Layout(gtx)
										})
									})
								}),

								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									if len(orderWorking) == 0 {
										lbl := material.Body1(th, "No files selected.")
										lbl.Color = colHint
										return lbl.Layout(gtx)
									}

									if len(orderUps) != len(orderWorking) {
										n := len(orderWorking)
										orderUps = make([]*widget.Clickable, n)
										orderDowns = make([]*widget.Clickable, n)
										orderRemoves = make([]*widget.Clickable, n)
										for i := 0; i < n; i++ {
											orderUps[i] = new(widget.Clickable)
											orderDowns[i] = new(widget.Clickable)
											orderRemoves[i] = new(widget.Clickable)
										}
									}

									children := make([]layout.FlexChild, 0, len(orderWorking)*2)
									for i, path := range orderWorking {
										p := path
										up := orderUps[i]
										down := orderDowns[i]
										rem := orderRemoves[i]

										children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											child := gtx
											child.Constraints.Min.X = 0
											child.Constraints.Max.X = gtx.Constraints.Max.X

											return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(child,
												layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
													ch := gtx
													ch.Constraints.Min.X = 0
													ch.Constraints.Max.X = gtx.Constraints.Max.X
													in := layout.Inset{Left: unit.Dp(8), Right: unit.Dp(8), Top: unit.Dp(6), Bottom: unit.Dp(6)}
													lbl := material.Body2(th, p)
													lbl.Color = colFg
													return in.Layout(ch, lbl.Layout)
												}),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													idx := -1
													for j, v := range orderWorking {
														if v == p {
															idx = j
															break
														}
													}
													if up.Clicked(gtx) && idx > 0 {
														orderWorking[idx], orderWorking[idx-1] = orderWorking[idx-1], orderWorking[idx]
														w.Invalidate()
													}
													btn := material.Button(th, up, "Up")
													btn.Background = colSurface
													btn.Color = colFg
													return layout.Inset{Right: unit.Dp(6)}.Layout(gtx, btn.Layout)
												}),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													idx := -1
													for j, v := range orderWorking {
														if v == p {
															idx = j
															break
														}
													}
													if down.Clicked(gtx) && idx >= 0 && idx < len(orderWorking)-1 {
														orderWorking[idx], orderWorking[idx+1] = orderWorking[idx+1], orderWorking[idx]
														w.Invalidate()
													}
													btn := material.Button(th, down, "Down")
													btn.Background = colSurface
													btn.Color = colFg
													return layout.Inset{Right: unit.Dp(6)}.Layout(gtx, btn.Layout)
												}),
												layout.Rigid(func(gtx layout.Context) layout.Dimensions {
													idx := -1
													for j, v := range orderWorking {
														if v == p {
															idx = j
															break
														}
													}
													if rem.Clicked(gtx) && idx >= 0 && idx < len(orderWorking) {
														orderWorking = append(orderWorking[:idx], orderWorking[idx+1:]...)
														orderUps = append(orderUps[:idx], orderUps[idx+1:]...)
														orderDowns = append(orderDowns[:idx], orderDowns[idx+1:]...)
														orderRemoves = append(orderRemoves[:idx], orderRemoves[idx+1:]...)
														w.Invalidate()
														return layout.Dimensions{}
													}
													btn := material.Button(th, rem, "Remove")
													btn.Background = colPrimary
													btn.Color = colContrastFg
													return btn.Layout(gtx)
												}),
											)
										}))

										children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
												return layout.Spacer{Height: unit.Dp(4)}.Layout(gtx)
											})
										}))
									}

									return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
								}),

								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									return layout.Inset{Top: unit.Dp(12)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
										return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
												layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
													return layout.W.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
														if orderCancel.Clicked(gtx) {
															orderInited = false
															if state.mode == "encrypt" {
																currentView = ViewEncrypt
															} else {
																currentView = ViewDecrypt
															}
														}
														btn := material.Button(th, orderCancel, "Cancel")
														btn.Background = colSurface
														btn.Color = colHint
														return layout.Inset{Left: unit.Dp(4)}.Layout(gtx, btn.Layout)
													})
												}),
												layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
													return layout.E.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
														if orderDone.Clicked(gtx) {
															state.keyfiles = append([]string(nil), orderWorking...)
															if len(state.keyfiles) == 0 {
																status.keyfileLabel = "None selected"
															} else if len(state.keyfiles) == 1 {
																status.keyfileLabel = "Using 1 keyfile"
															} else {
																status.keyfileLabel = fmt.Sprintf("Using %d keyfiles", len(state.keyfiles))
															}

															if state.mode == "encrypt" {
																currentView = ViewEncrypt
															} else {
																currentView = ViewDecrypt
															}
														}
														btn := material.Button(th, orderDone, "Done")
														btn.Background = colPrimary
														btn.Color = colContrastFg
														return layout.Inset{Right: unit.Dp(4)}.Layout(gtx, btn.Layout)
													})
												}),
											)
										})
									})
								}),
							)
						})
					}),
				)

			case ViewDecrypt:
				layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					maxW := gtx.Dp(unit.Dp(600))
					if gtx.Constraints.Max.X > maxW {
						gtx.Constraints.Max.X = maxW
					}

					editorBox := func(gtx layout.Context, ed *widget.Editor) layout.Dimensions {
						gtx.Constraints.Min.X = gtx.Constraints.Max.X
						h := gtx.Dp(unit.Dp(40))
						gtx.Constraints.Min.Y = h
						gtx.Constraints.Max.Y = h
						return layout.UniformInset(unit.Dp(4)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							rect := imageRect(gtx.Constraints.Max.X, h)
							paintFill(gtx, colSurface, rect)

							e := material.Editor(th, ed, "")
							e.Color = colFg
							e.HintColor = colHint
							return e.Layout(gtx)
						})
					}

					passwordHeader := func(gtx layout.Context) layout.Dimensions {
						toggleWidth := gtx.Dp(unit.Dp(72))
						sideInset := gtx.Dp(unit.Dp(4))
						fixedW := toggleWidth + sideInset*2

						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								gtx.Constraints.Min.X = toggleWidth
								gtx.Constraints.Max.X = toggleWidth
								for toggleHide.Clicked(gtx) {
									hidePass = !hidePass
									if hidePass {
										passEditor.Mask = '*'
										confirmEditor.Mask = '*'
									} else {
										passEditor.Mask = 0
										confirmEditor.Mask = 0
									}
								}
								label := "Show"
								if !hidePass {
									label = "Hide"
								}
								btn := material.Button(th, toggleHide, label)
								btn.Background = colSecondary
								btn.Color = colContrastFg
								return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(4), Bottom: unit.Dp(8)}.Layout(gtx, btn.Layout)
							}),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									lbl := material.Body1(th, "Password")
									lbl.Color = colFg
									return layout.Inset{Bottom: unit.Dp(8)}.Layout(gtx, lbl.Layout)
								})
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								gtx.Constraints.Min.X = fixedW
								gtx.Constraints.Max.X = fixedW
								return layout.Dimensions{Size: image.Pt(fixedW, 0)}
							}),
						)
					}

					return material.List(th, decryptList).Layout(gtx, 1, func(gtx layout.Context, index int) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								h := material.H4(th, "Decrypt")
								h.Color = colFg
								return layout.Inset{Bottom: unit.Dp(20)}.Layout(gtx, h.Layout)
							}),
							layout.Rigid(passwordHeader),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return editorBox(gtx, passEditor)
							}),

							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										return layout.Inset{Left: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											lbl := material.Body1(th, "Keyfiles")
											lbl.Color = colFg
											return layout.Inset{Right: unit.Dp(12)}.Layout(gtx, lbl.Layout)
										})
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										statusText := "Correct order not required"
										if state.keyfileOrdered {
											statusText = "Correct order required"
										}
										lbl := material.Body2(th, statusText)
										lbl.Color = colFg
										return layout.Inset{Right: unit.Dp(12)}.Layout(gtx, lbl.Layout)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										for orderKeyfiles.Clicked(gtx) {
											currentView = ViewOrder
										}

										btn := material.Button(th, orderKeyfiles, "Order keyfiles")
										btn.Background = colSurface
										btn.Color = colFg
										return layout.Inset{Right: unit.Dp(8)}.Layout(gtx, btn.Layout)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										for editKeyfiles.Clicked(gtx) {
											defPath := ""
											paths, err := zenity.SelectFileMultiple(
												zenity.Filename(defPath),
												zenity.FileFilter{"All files", []string{"*"}, true},
											)
											if err != nil {
												if err == zenity.ErrCanceled {
													continue
												}
												status.main = "Failed to open file chooser"
												status.mainColor = RED
												continue
											}

											state.keyfiles = append([]string(nil), paths...)
											orderWorking = append([]string(nil), state.keyfiles...)

											if len(state.keyfiles) == 0 {
												status.keyfileLabel = "None selected"
											} else if len(state.keyfiles) == 1 {
												status.keyfileLabel = "Using 1 keyfile"
											} else {
												status.keyfileLabel = fmt.Sprintf("Using %d keyfiles", len(state.keyfiles))
											}

											orderUps = nil
											orderDowns = nil
											orderRemoves = nil
											orderInited = false
										}

										btn := material.Button(th, editKeyfiles, "Edit")
										btn.Background = colSurface
										btn.Color = colFg
										return layout.Inset{Right: unit.Dp(8)}.Layout(gtx, btn.Layout)
									}),
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										h := gtx.Dp(unit.Dp(36))
										gtx.Constraints.Min.Y = h
										gtx.Constraints.Max.Y = h
										rect := imageRect(gtx.Constraints.Max.X, h)
										paintFill(gtx, colSurfaceAlt, rect)
										lbl := material.Body2(th, status.keyfileLabel)
										lbl.Color = colHint
										return layout.Inset{Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx, lbl.Layout)
									}),
								)
							}),

							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Spacer{Height: unit.Dp(12)}.Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								lbl := material.Body1(th, "Comments")
								lbl.Color = colFg
								return layout.Inset{Left: unit.Dp(4), Top: unit.Dp(12), Bottom: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return lbl.Layout(gtx)
								})
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								h := gtx.Dp(unit.Dp(120))
								gtx.Constraints.Min.X = gtx.Constraints.Max.X
								gtx.Constraints.Min.Y = h
								gtx.Constraints.Max.Y = h
								return layout.UniformInset(unit.Dp(4)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									rect := imageRect(gtx.Constraints.Max.X, h)
									paintFill(gtx, colSurface, rect)

									e := material.Editor(th, commentsEditor, state.comments)
									e.Color = colFg
									e.Hint = "Optional comment..."
									e.HintColor = colHint
									return e.Layout(gtx)
								})
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								lbl := material.Body1(th, "Advanced")
								lbl.Color = colFg
								return layout.Inset{Left: unit.Dp(4), Top: unit.Dp(12), Bottom: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
									return lbl.Layout(gtx)
								})
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								children := []layout.FlexChild{
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										cb := material.CheckBox(th, forceDecryptChk, "Force decrypt")
										cb.Color = colFg
										return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(12)}.Layout(gtx, cb.Layout)
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										cb := material.CheckBox(th, deleteVolumeChk, "Delete volume")
										cb.Color = colFg
										return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(12)}.Layout(gtx, cb.Layout)
									}),
								}

								if strings.HasSuffix(state.inputFile, ".zip.pcv") {
									children = append(children,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											cb := material.CheckBox(th, autoUnzipChk, "Auto unzip")
											cb.Color = colFg
											return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(12)}.Layout(gtx, cb.Layout)
										}),
									)
									if !autoUnzipChk.Value {
										sameLevelChk.Value = false
									}
									children = append(children,
										layout.Rigid(func(gtx layout.Context) layout.Dimensions {
											cb := material.CheckBox(th, sameLevelChk, "Same level")
											cb.Color = colFg
											return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(12)}.Layout(gtx, cb.Layout)
										}),
									)
								}

								return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
							}),

							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										lbl := material.Body1(th, "Save output as")
										lbl.Color = colFg
										return layout.Inset{Left: unit.Dp(4), Right: unit.Dp(12)}.Layout(gtx, lbl.Layout)
									}),
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
											layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
												h := gtx.Dp(unit.Dp(36))
												gtx.Constraints.Min.Y = h
												gtx.Constraints.Max.Y = h

												availW := gtx.Constraints.Max.X
												child := gtx
												child.Constraints.Min.X = 0
												child.Constraints.Max.X = availW

												rect := imageRect(availW, h)
												paintFill(child, colSurface, rect)

												lbl := material.Body2(th, state.outputFile)
												lbl.Color = colFg
												return layout.Inset{Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx, lbl.Layout)
											}),
											layout.Rigid(func(gtx layout.Context) layout.Dimensions {
												w := gtx.Dp(unit.Dp(92))
												h := gtx.Dp(unit.Dp(36))
												gtx.Constraints.Min.X = w
												gtx.Constraints.Max.X = w
												gtx.Constraints.Min.Y = h
												gtx.Constraints.Max.Y = h

												for changeBtn.Clicked(gtx) {
													startDir := ""
													if len(state.onlyFiles) > 0 {
														startDir = filepath.Dir(state.onlyFiles[0])
													} else if len(state.onlyFolders) > 0 {
														startDir = filepath.Dir(state.onlyFolders[0])
													}

													tmp := strings.TrimSuffix(filepath.Base(state.outputFile), ".pcv")
													initName := strings.TrimSuffix(tmp, filepath.Ext(tmp))
													if state.mode == "encrypt" && (len(state.allFiles) > 1 || len(state.onlyFolders) > 0 || state.compress) {
														initName = "encrypted-" + strconv.Itoa(int(time.Now().Unix()))
													}

													options := []zenity.Option{
														zenity.Filename(initName),
														zenity.ConfirmOverwrite(),
													}
													if startDir != "" {
														prevDir, _ := os.Getwd()
														_ = os.Chdir(startDir)
														defer os.Chdir(prevDir)
													}

													file, err := zenity.SelectFileSave(options...)
													if err != nil {
														if err == zenity.ErrCanceled {
															continue
														}
														status.main = "Failed to open save dialog"
														status.mainColor = RED
														continue
													}
													if file == "" {
														continue
													}

													base := strings.Split(filepath.Base(file), ".")[0]
													file = filepath.Join(filepath.Dir(file), base)

													if state.mode == "encrypt" {
														if len(state.allFiles) > 1 || len(state.onlyFolders) > 0 || state.compress {
															file += ".zip.pcv"
														} else {
															file += filepath.Ext(state.inputFile) + ".pcv"
														}
													} else {
														if strings.HasSuffix(state.inputFile, ".zip.pcv") {
															file += ".zip"
														} else {
															tmp2 := strings.TrimSuffix(filepath.Base(state.inputFile), ".pcv")
															file += filepath.Ext(tmp2)
														}
													}

													state.outputFile = file
													status.main = "Ready"
													status.mainColor = WHITE
												}
												btn := material.Button(th, changeBtn, "Change")
												btn.Background = colSecondary
												btn.Color = colContrastFg
												return btn.Layout(gtx)
											}),
										)
									}),
								)
							}),

							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								sideW := gtx.Dp(unit.Dp(92))
								btnH := gtx.Dp(unit.Dp(40))

								backClickable := selectFiles

								for backClickable.Clicked(gtx) {
									currentView = ViewStart
								}
								for clearBtn.Clicked(gtx) {
									save := state.outputFile
									state = WorkOptions{}
									state.outputFile = save
									passEditor.SetText("")
									commentsEditor.SetText("")
									forceDecryptChk.Value = false
									deleteVolumeChk.Value = false
									deleteChk.Value = false
									autoUnzipChk.Value = false
									sameLevelChk.Value = false
									hidePass = true
									passEditor.Mask = '*'
								}

								for startBtn.Clicked(gtx) {
									syncWidgetsToState()
									mu.Lock()
									status.working = true
									status.showProgress = true
									status.progress = 0
									status.progressInfo = "Starting..."
									mu.Unlock()

									// Start button should be disabled if these conditions are true; don't do anything if so
									if (len(state.keyfiles) == 0 && state.password == "") || (state.mode == "encrypt" && state.password != state.confirmPassword) {
										continue
									}

									if state.keyfile && state.keyfiles == nil {
										status.main = "Please select your keyfiles"
										status.mainColor = RED
										continue
									}
									tmp, err := strconv.Atoi(state.splitSize)
									if state.split && (state.splitSize == "" || err != nil || tmp <= 0) {
										status.main = "Invalid chunk size"
										status.mainColor = RED
										continue
									}

									// Check if output file already exists
									_, err = os.Stat(state.outputFile)

									// Check if any split chunks already exist
									if state.split {
										names, err2 := filepath.Glob(state.outputFile + ".*")
										if err2 != nil {
											panic(err2)
										}
										if len(names) > 0 {
											err = nil
										} else {
											err = os.ErrNotExist
										}
									}

									// If files already exist, show the overwrite modal
									if err == nil && !state.recursively {
										ok := zenity.Question("Outputfile already exists. Overwrite?",
											zenity.Title("Question"),
											zenity.QuestionIcon,
										)
										if ok != nil {
											continue
										}
									}
									status.showProgress = true
									fastDecode = true
									status.canCancel = true
									currentView = ViewProgress
									if !state.recursively {
										go func() {
											work()
											status.working = false
											status.showProgress = false
											currentView = ViewStart

										}()
									} else {
										// Store variables as they will be cleared
										oldPassword := state.password
										oldKeyfile := state.keyfile
										oldKeyfiles := state.keyfiles
										oldKeyfileOrdered := state.keyfileOrdered
										oldKeyfileLabel := status.keyfileLabel
										oldComments := state.comments
										oldParanoid := state.paranoid
										oldReedsolo := state.reedSolomon
										oldDeniability := state.deniability
										oldSplit := state.split
										oldSplitSize := state.splitSize
										oldSplitSelected := state.splitSelected
										oldDelete := state.delete
										files := state.allFiles
										go func() {
											for _, file := range files {
												// Simulate dropping the file
												onDrop([]string{file})

												// Restore variables and options
												state.password = oldPassword
												state.confirmPassword = oldPassword
												state.keyfile = oldKeyfile
												state.keyfiles = oldKeyfiles
												state.keyfileOrdered = oldKeyfileOrdered
												status.keyfileLabel = oldKeyfileLabel
												state.comments = oldComments
												state.paranoid = oldParanoid
												state.reedSolomon = oldReedsolo
												if state.mode != "decrypt" {
													state.deniability = oldDeniability
												}
												state.split = oldSplit
												state.splitSize = oldSplitSize
												state.splitSelected = oldSplitSelected
												state.delete = oldDelete

												work()
												if !status.working {
													resetUI()
													cancel(nil, nil)
													status.showProgress = false
													currentView = ViewStart
													continue
												}
											}
											status.working = false
											status.showProgress = false
											currentView = ViewStart
											w.Invalidate()
										}()
									}
								}

								return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										gtx.Constraints.Min.X = sideW
										gtx.Constraints.Max.X = sideW
										gtx.Constraints.Min.Y = btnH
										gtx.Constraints.Max.Y = btnH
										btn := material.Button(th, backClickable, "Back")
										btn.Background = colPrimary
										btn.Color = colContrastFg
										return layout.Inset{Left: unit.Dp(8)}.Layout(gtx, btn.Layout)
									}),
									layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
										return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
											w := gtx.Dp(unit.Dp(160))
											h := gtx.Dp(unit.Dp(52))
											gtx.Constraints.Min.X = w
											gtx.Constraints.Max.X = w
											gtx.Constraints.Min.Y = h
											gtx.Constraints.Max.Y = h
											btn := material.Button(th, startBtn, "Start")
											btn.Background = colPrimary
											btn.Color = colContrastFg
											return btn.Layout(gtx)
										})
									}),
									layout.Rigid(func(gtx layout.Context) layout.Dimensions {
										gtx.Constraints.Min.X = sideW
										gtx.Constraints.Max.X = sideW
										gtx.Constraints.Min.Y = btnH
										gtx.Constraints.Max.Y = btnH
										btn := material.Button(th, clearBtn, "Clear")
										btn.Background = colSurface
										btn.Color = colHint
										return layout.Inset{Right: unit.Dp(8)}.Layout(gtx, btn.Layout)
									}),
								)
							}),
						)
					})
				})
			case ViewProgress:
				layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					maxW := gtx.Dp(unit.Dp(600))
					if gtx.Constraints.Max.X > maxW {
						gtx.Constraints.Max.X = maxW
					}

					p := status.progress
					msg := status.popup

					return material.List(th, progressList).Layout(gtx, 1, func(gtx layout.Context, index int) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								h := material.H5(th, "Progress")
								h.Color = colFg
								return layout.Inset{Bottom: unit.Dp(12)}.Layout(gtx, h.Layout)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								barH := gtx.Dp(unit.Dp(16))
								barW := gtx.Constraints.Max.X
								bgRect := imageRect(barW, barH)
								paintFill(gtx, colSurface, bgRect)

								if p < 0 {
									p = 0
								}
								if p > 1 {
									p = 1
								}
								fillW := int(float32(barW) * p)
								if fillW > 0 {
									fillRect := imageRect(fillW, barH)
									fillCol := colPrimary
									paintFill(gtx, fillCol, fillRect)
								}

								perc := int(p * 100)
								lbl := material.Body2(th, strconv.Itoa(perc)+"%")
								lbl.Color = colContrastFg
								return layout.Stack{Alignment: layout.Center}.Layout(gtx,
									layout.Expanded(func(gtx layout.Context) layout.Dimensions {
										gtx.Constraints.Min.X = barW
										gtx.Constraints.Max.X = barW
										gtx.Constraints.Min.Y = barH
										gtx.Constraints.Max.Y = barH
										return layout.Dimensions{Size: image.Point{X: barW, Y: barH}}
									}),
									layout.Stacked(func(gtx layout.Context) layout.Dimensions {
										return layout.Center.Layout(gtx, lbl.Layout)
									}),
								)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if msg == "" {
									msg = "Working..."
								}
								lbl := material.Body1(th, msg)
								lbl.Color = colFg
								return layout.Inset{Top: unit.Dp(12)}.Layout(gtx, lbl.Layout)
							}),
						)
					})
				})
			}

			syncWidgetsToState()

			e.Frame(gtx.Ops)
		}
	}
}

func imageRect(w, h int) image.Rectangle {
	return image.Rectangle{Min: image.Point{X: 0, Y: 0}, Max: image.Point{X: w, Y: h}}
}

func paintFill(gtx layout.Context, col color.NRGBA, r image.Rectangle) {
	defer clip.Rect(r).Push(gtx.Ops).Pop()
	paint.ColorOp{Color: col}.Add(gtx.Ops)
	paint.PaintOp{}.Add(gtx.Ops)
}

func syncStateToWidgets() {
	paranoidChk.Value = state.paranoid
	compressChk.Value = state.compress
	rsChk.Value = state.reedSolomon
	deniabilityChk.Value = state.deniability
	recursiveChk.Value = state.recursively
	splitChk.Value = state.split
	forceDecryptChk.Value = state.keep
	autoUnzipChk.Value = state.autoUnzip
	sameLevelChk.Value = state.sameLevel
	requireOrder.Value = state.keyfileOrdered
	deleteChk.Value = state.delete
	deleteVolumeChk.Value = state.delete

	if passEditor.Text() != state.password {
		passEditor.SetText(state.password)
	}
	if confirmEditor.Text() != state.confirmPassword {
		confirmEditor.SetText(state.confirmPassword)
	}
	if commentsEditor.Text() != state.comments {
		commentsEditor.SetText(state.comments)
	}
	if splitEditor.Text() != state.splitSize {
		splitEditor.SetText(state.splitSize)
	}
	splitCycleIndex = int(state.splitSelected) % 4
	if splitCycleIndex < 0 {
		splitCycleIndex = 0
	}

	progressPct = status.progress
	progressMsg = status.progressInfo
}

func syncWidgetsToState() {
	state.paranoid = paranoidChk.Value
	state.compress = compressChk.Value
	state.reedSolomon = rsChk.Value
	state.deniability = deniabilityChk.Value
	state.recursively = recursiveChk.Value
	state.split = splitChk.Value
	state.keep = forceDecryptChk.Value
	state.autoUnzip = autoUnzipChk.Value
	state.sameLevel = sameLevelChk.Value
	state.passgenLength = int32(lengthVal)
	state.passgenLower = lowercase.Value
	state.passgenUpper = uppercase.Value
	state.passgenNums = numbers.Value
	state.passgenSymbols = symbols.Value

	if state.mode == "encrypt" {
		state.delete = deleteChk.Value
		state.keyfileOrdered = requireOrder.Value
		state.comments = commentsEditor.Text()
	} else {
		state.delete = deleteVolumeChk.Value
	}

	state.password = passEditor.Text()
	state.confirmPassword = confirmEditor.Text()
	state.splitSize = splitEditor.Text()
	state.splitSelected = int32(splitCycleIndex)

}
