// SPDX-FileCopyrightText: 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"runtime/debug"

	"go.uber.org/zap"
)

// RecoverWithLog recovers from panic and logs the error and stack trace using the provided logger
func RecoverWithLog(logger *zap.SugaredLogger) {
	if p := recover(); p != nil {
		logger.Errorw("panic recovered", "error", p, "stack", string(debug.Stack()))
	}
}
