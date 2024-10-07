import 'package:flutter/material.dart';

class FadeAnimation extends StatefulWidget {
  final double delay;
  final Widget child;

  FadeAnimation(this.delay, this.child);

  @override
  _FadeAnimationState createState() => _FadeAnimationState();
}

class _FadeAnimationState extends State<FadeAnimation> with TickerProviderStateMixin {
  late AnimationController controller;
  late Animation<double> opacityTween;
  late Animation<double> translateYTween;

  @override
  void initState() {
    super.initState();

    controller = AnimationController(
      duration: const Duration(milliseconds: 500),
      vsync: this,
    );

    opacityTween = Tween<double>(begin: 0.0, end: 1.0).animate(controller);
    translateYTween = Tween<double>(begin: -30.0, end: 0.0).animate(controller);

    // Start the animation
    controller.forward();
  }

  @override
  void dispose() {
    controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return TweenAnimationBuilder(
      tween: Tween(begin: 0.0, end: 1.0),
      duration: controller.duration!,
      builder: (context, double opacity, child) {
        return AnimatedBuilder(
          animation: controller,
          builder: (context, child) {
            return Opacity(
              opacity: opacity * opacityTween.value,
              child: Transform.translate(
                offset: Offset(0, translateYTween.value),
                child: child,
              ),
            );
          },
          child: widget.child,
        );
      },
    );
  }
}

